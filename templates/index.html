<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>محلل الروابط الأمني الاحترافي</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f7f9fc; }
        .text-shadow-custom { text-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
        /* تصميم مخصص ليكون محترفًا وجذابًا */
        .risk-color-Critical { background-color: #fef2f2; border-color: #f87171; color: #b91c1c; }
        .risk-color-High { background-color: #fff7ed; border-color: #fb923c; color: #c2410c; }
        .risk-color-Medium { background-color: #fffbeb; border-color: #facc15; color: #a16207; }
        .risk-color-Low { background-color: #f0fdf4; border-color: #4ade80; color: #166534; }
        .risk-color-default { background-color: #e0f2f1; border-color: #2dd4bf; color: #0f766e; }

    </style>
</head>
<body class="p-4 md:p-8">

    <div class="max-w-4xl mx-auto bg-white shadow-2xl rounded-xl p-6 md:p-10 border border-gray-100">

        <h1 class="text-3xl md:text-4xl font-extrabold text-gray-900 mb-2 text-shadow-custom">
            🛡️ محلل الروابط الأمني الاحترافي
        </h1>
        <p class="text-gray-500 mb-8">
            قم بإدخال أي رابط للتحقق من سلامته عبر تطبيق أكثر من 40 قاعدة فحص متقدمة.
        </p>

        <div class="flex flex-col sm:flex-row gap-4 mb-8">
            <input type="url" id="linkInput" placeholder="أدخل الرابط المراد تحليله هنا (مثل: https://example.com)"
                   class="flex-grow p-3 border-2 border-indigo-200 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 transition duration-150 outline-none"
                   value=""
                   aria-label="حقل إدخال الرابط">
            <button id="analyzeButton" onclick="analyzeLink()"
                    class="w-full sm:w-auto px-6 py-3 bg-indigo-600 text-white font-semibold rounded-lg shadow-md hover:bg-indigo-700 transition duration-300 transform hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50">
                تحليل الرابط
            </button>
        </div>

        <div id="messageBox" class="p-3 mb-4 rounded-lg hidden" role="alert"></div>

        <div id="resultsArea" class="hidden">
            <h2 class="text-2xl font-bold text-gray-800 mb-4 border-b pb-2">ملخص التحليل الأمني</h2>

            <div id="summaryCard" class="p-6 rounded-xl border-4 mb-6 transition-all duration-500 risk-color-default">
                <p class="text-sm font-medium mb-1">مستوى الخطورة:</p>
                <h3 id="riskScoreDisplay" class="text-4xl font-extrabold">جاري الفحص...</h3>
                <p id="resultMessageDisplay" class="mt-2 text-lg font-medium"></p>
                
                <div class="mt-4 text-sm flex flex-col space-y-1">
                    <p><strong>الرابط الذي تم إدخاله:</strong> <span id="linkInputDisplay" class="font-mono break-all text-indigo-600"></span></p>
                    <p><strong>الرابط النهائي (بعد التوجيه):</strong> <span id="linkFinalDisplay" class="font-mono break-all text-indigo-600"></span></p>
                    <p><strong>نقاط الاشتباه الإجمالية:</strong> <span id="pointsDisplay" class="font-bold">0</span> نقطة</p>
                    <p><strong>حالة جلب المحتوى:</strong> <span id="contentStatusDisplay" class="font-medium"></span></p>
                </div>
            </div>

            <h2 class="text-2xl font-bold text-gray-800 mb-4 border-b pb-2">القواعد الأمنية المخترقة (<span id="warningsCount">0</span>)</h2>
            <div id="violatedRulesList" class="space-y-4">
                </div>
            
            <p id="noViolationsMessage" class="hidden p-4 text-center text-gray-500 bg-gray-50 rounded-lg">
                🎉 لم يتم اكتشاف أي مخالفات أمنية واضحة.
            </p>
        </div>

    </div>

    <script>
        const linkInput = document.getElementById('linkInput');
        const analyzeButton = document.getElementById('analyzeButton');
        const messageBox = document.getElementById('messageBox');
        const resultsArea = document.getElementById('resultsArea');
        const summaryCard = document.getElementById('summaryCard');
        const riskScoreDisplay = document.getElementById('riskScoreDisplay');
        const resultMessageDisplay = document.getElementById('resultMessageDisplay');
        const linkInputDisplay = document.getElementById('linkInputDisplay');
        const linkFinalDisplay = document.getElementById('linkFinalDisplay');
        const pointsDisplay = document.getElementById('pointsDisplay');
        const contentStatusDisplay = document.getElementById('contentStatusDisplay');
        const violatedRulesList = document.getElementById('violatedRulesList');
        const warningsCount = document.getElementById('warningsCount');
        const noViolationsMessage = document.getElementById('noViolationsMessage');
        const apiUrl = '/analyze';

        // دالة لعرض رسالة خطأ أو نجاح
        function showMessage(type, message) {
            messageBox.classList.remove('hidden', 'bg-red-100', 'border-red-400', 'text-red-700', 'bg-green-100', 'border-green-400', 'text-green-700');
            messageBox.innerHTML = message;

            if (type === 'error') {
                messageBox.classList.add('bg-red-100', 'border', 'border-red-400', 'text-red-700');
            } else if (type === 'success') {
                messageBox.classList.add('bg-green-100', 'border', 'border-green-400', 'text-green-700');
            }
        }

        // دالة لتحديث لون بطاقة الملخص بناءً على درجة الخطورة
        function updateRiskCardColor(riskScore) {
            // إزالة الألوان السابقة
            summaryCard.classList.remove('risk-color-Critical', 'risk-color-High', 'risk-color-Medium', 'risk-color-Low', 'risk-color-default');
            
            // تطبيق اللون الجديد
            if (riskScore === 'Critical') {
                summaryCard.classList.add('risk-color-Critical');
            } else if (riskScore === 'High') {
                summaryCard.classList.add('risk-color-High');
            } else if (riskScore === 'Medium') {
                summaryCard.classList.add('risk-color-Medium');
            } else {
                summaryCard.classList.add('risk-color-Low');
            }
        }

        // دالة معالجة التحليل
        async function analyzeLink() {
            const link = linkInput.value.trim();
            resultsArea.classList.add('hidden');
            messageBox.classList.add('hidden');
            analyzeButton.disabled = true;
            analyzeButton.textContent = 'جاري التحليل...';
            summaryCard.classList.remove('risk-color-Critical', 'risk-color-High', 'risk-color-Medium', 'risk-color-Low');
            summaryCard.classList.add('risk-color-default');
            riskScoreDisplay.textContent = 'جاري الفحص...';
            
            if (!link) {
                showMessage('error', 'الرجاء إدخال رابط صالح للتحليل.');
                analyzeButton.disabled = false;
                analyzeButton.textContent = 'تحليل الرابط';
                return;
            }

            try {
                const response = await fetch(apiUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ link: link })
                });

                const result = await response.json();

                if (!response.ok || result.status.includes('error') || result.status.includes('validation')) {
                    showMessage('error', result.message || 'حدث خطأ غير متوقع أثناء التحليل.');
                    return;
                }

                // عرض النتائج الرئيسية
                resultsArea.classList.remove('hidden');
                updateRiskCardColor(result.risk_score);
                riskScoreDisplay.textContent = result.risk_score;
                resultMessageDisplay.textContent = result.result_message;
                linkInputDisplay.textContent = result.link_input;
                linkFinalDisplay.textContent = result.link_final;
                pointsDisplay.textContent = result.suspicious_points;
                contentStatusDisplay.textContent = result.page_content_status;
                warningsCount.textContent = result.detected_warnings;

                // عرض القواعد المخترقة بالتفصيل
                violatedRulesList.innerHTML = '';
                
                if (result.violated_rules && result.violated_rules.length > 0) {
                    noViolationsMessage.classList.add('hidden');
                    result.violated_rules.forEach(rule => {
                        const ruleElement = document.createElement('div');
                        ruleElement.className = 'p-4 border border-red-200 bg-red-50 rounded-lg shadow-sm';
                        ruleElement.innerHTML = `
                            <p class="font-bold text-red-800 text-lg mb-1">${rule.name}</p>
                            <p class="text-sm text-gray-700"><strong>وصف الخطر:</strong> ${rule.risk_description}</p>
                            <p class="text-xs text-red-600 mt-1"><strong>نقاط الخطورة المضافة:</strong> +${rule.points_added}</p>
                        `;
                        violatedRulesList.appendChild(ruleElement);
                    });
                } else {
                    noViolationsMessage.classList.remove('hidden');
                }

                showMessage('success', result.message);
                
                // التعديل الذي يضمن رؤية النتائج على الأجهزة الصغيرة
                window.scrollTo({ top: 0, behavior: 'smooth' }); 

            } catch (error) {
                console.error("Error during analysis:", error);
                showMessage('error', 'فشل الاتصال بالخادم. تحقق من الرابط أو اتصال الشبكة.');
            } finally {
                analyzeButton.disabled = false;
                analyzeButton.textContent = 'تحليل الرابط';
            }
        }
    </script>
</body>
</html>
