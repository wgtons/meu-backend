const express = require('express');
const dns = require('dns').promises;
const path = require('path');
const cors = require('cors'); // Movido para o topo corretamente

const app = express();
const PORT = process.env.PORT || 5000;

// Configuração correta do CORS logo após inicializar o app
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));


app.options('*', cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/analyze', async (req, res) => {
    const { domain, sector } = req.body;
    
    if (!domain) {
        return res.status(400).json({ error: 'Domínio é obrigatório.' });
    }

    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].trim();
    console.log(`\n====================================`);
    console.log(`[AUDITORIA INICIADA] Domínio: ${cleanDomain}`);

    let spfScore = 0;
    let dmarcScore = 0;
    let rawSpf = null;
    let rawDmarc = null;

    // 1. Consulta SPF Nativa Direta
    try {
        const txtRecords = await dns.resolveTxt(cleanDomain);
        const flatRecords = txtRecords.map(chunks => chunks.join(' '));
        rawSpf = flatRecords.find(rec => rec.toLowerCase().startsWith('v=spf1'));
        
        if (rawSpf) {
            console.log(`[LOG] SPF Encontrado: ${rawSpf}`);
            if (rawSpf.toLowerCase().includes('-all')) spfScore = 4.0;
            else if (rawSpf.toLowerCase().includes('~all')) spfScore = 3.0;
            else spfScore = 2.0;
        } else {
            console.log(`[LOG] Nenhum registro SPF TXT na raiz.`);
        }
    } catch (e) {
        console.log(`[LOG] Falha ao consultar SPF no DNS local: ${e.message}`);
    }

    // 2. Consulta DMARC Nativa Direta
    try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${cleanDomain}`);
        const flatDmarc = dmarcRecords.map(chunks => chunks.join(' '));
        rawDmarc = flatDmarc.find(rec => rec.toLowerCase().startsWith('v=dmarc1'));

        if (rawDmarc) {
            console.log(`[LOG] DMARC Encontrado: ${rawDmarc}`);
            if (rawDmarc.toLowerCase().includes('p=reject')) dmarcScore = 5.0;
            else if (rawDmarc.toLowerCase().includes('p=quarantine')) dmarcScore = 4.0;
            else if (rawDmarc.toLowerCase().includes('p=none')) dmarcScore = 1.5;
        } else {
            console.log(`[LOG] Nenhum registro DMARC encontrado.`);
        }
    } catch (e) {
        console.log(`[LOG] Falha ao consultar DMARC no DNS local: ${e.message}`);
    }

    // 3. Forçar Nota 10 se houver evidência real de Reject no texto bruto
    let finalScore = 1.0 + spfScore + dmarcScore;
    if (rawDmarc && rawDmarc.toLowerCase().includes('p=reject') && spfScore > 0) {
        finalScore = 10.0;
    }

    if (finalScore > 10.0) finalScore = 10.0;

    let perimeterStatus = finalScore >= 8.5 ? 'Protegido' : 'Vulnerável';
    if (finalScore < 4.0) perimeterStatus = 'Crítico';

    const sectorBaseLosses = { 'Indústria & Manufatura': 1400000, 'Varejo & Operações': 980000, 'Saúde & Hospitais': 2100000 };
    const baseLoss = sectorBaseLosses[sector] || 1200000;
    const riskFactor = (10 - finalScore) / 9;
    const computedLoss = finalScore >= 9.5 ? 0 : Math.round(baseLoss * riskFactor);

    console.log(`[RESULTADO FINAL] Nota Gerada: ${finalScore} | Status: ${perimeterStatus}`);
    console.log(`====================================`);

    return res.json({
        domain: cleanDomain,
        sector,
        score: parseFloat(finalScore.toFixed(1)),
        status: perimeterStatus,
        loss: computedLoss,
        techDetails: { spf: rawSpf || "Inexistente", dmarc: rawDmarc || "Inexistente" }
    });
});

app.listen(PORT, () => console.log(`Servidor de Diagnóstico Local ativo na porta ${PORT}`));