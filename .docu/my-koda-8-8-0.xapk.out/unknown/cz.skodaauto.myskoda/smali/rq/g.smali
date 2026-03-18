.class public final Lrq/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/CharSequence;

.field public final b:Landroid/text/TextPaint;

.field public final c:I

.field public d:I

.field public e:Landroid/text/Layout$Alignment;

.field public f:I

.field public g:F

.field public h:F

.field public i:I

.field public j:Z

.field public k:Z

.field public l:Landroid/text/TextUtils$TruncateAt;

.field public m:Lrx/b;


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;Landroid/text/TextPaint;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrq/g;->a:Ljava/lang/CharSequence;

    .line 5
    .line 6
    iput-object p2, p0, Lrq/g;->b:Landroid/text/TextPaint;

    .line 7
    .line 8
    iput p3, p0, Lrq/g;->c:I

    .line 9
    .line 10
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    iput p1, p0, Lrq/g;->d:I

    .line 15
    .line 16
    sget-object p1, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 17
    .line 18
    iput-object p1, p0, Lrq/g;->e:Landroid/text/Layout$Alignment;

    .line 19
    .line 20
    const p1, 0x7fffffff

    .line 21
    .line 22
    .line 23
    iput p1, p0, Lrq/g;->f:I

    .line 24
    .line 25
    const/4 p1, 0x0

    .line 26
    iput p1, p0, Lrq/g;->g:F

    .line 27
    .line 28
    const/high16 p1, 0x3f800000    # 1.0f

    .line 29
    .line 30
    iput p1, p0, Lrq/g;->h:F

    .line 31
    .line 32
    const/4 p1, 0x1

    .line 33
    iput p1, p0, Lrq/g;->i:I

    .line 34
    .line 35
    iput-boolean p1, p0, Lrq/g;->j:Z

    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    iput-object p1, p0, Lrq/g;->l:Landroid/text/TextUtils$TruncateAt;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final a()Landroid/text/StaticLayout;
    .locals 7

    .line 1
    iget-object v0, p0, Lrq/g;->a:Ljava/lang/CharSequence;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, ""

    .line 6
    .line 7
    iput-object v0, p0, Lrq/g;->a:Ljava/lang/CharSequence;

    .line 8
    .line 9
    :cond_0
    iget v0, p0, Lrq/g;->c:I

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lrq/g;->a:Ljava/lang/CharSequence;

    .line 17
    .line 18
    iget v3, p0, Lrq/g;->f:I

    .line 19
    .line 20
    iget-object v4, p0, Lrq/g;->b:Landroid/text/TextPaint;

    .line 21
    .line 22
    const/4 v5, 0x1

    .line 23
    if-ne v3, v5, :cond_1

    .line 24
    .line 25
    int-to-float v3, v0

    .line 26
    iget-object v6, p0, Lrq/g;->l:Landroid/text/TextUtils$TruncateAt;

    .line 27
    .line 28
    invoke-static {v2, v4, v3, v6}, Landroid/text/TextUtils;->ellipsize(Ljava/lang/CharSequence;Landroid/text/TextPaint;FLandroid/text/TextUtils$TruncateAt;)Ljava/lang/CharSequence;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    :cond_1
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    iget v6, p0, Lrq/g;->d:I

    .line 37
    .line 38
    invoke-static {v3, v6}, Ljava/lang/Math;->min(II)I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    iput v3, p0, Lrq/g;->d:I

    .line 43
    .line 44
    iget-boolean v6, p0, Lrq/g;->k:Z

    .line 45
    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    iget v6, p0, Lrq/g;->f:I

    .line 49
    .line 50
    if-ne v6, v5, :cond_2

    .line 51
    .line 52
    sget-object v6, Landroid/text/Layout$Alignment;->ALIGN_OPPOSITE:Landroid/text/Layout$Alignment;

    .line 53
    .line 54
    iput-object v6, p0, Lrq/g;->e:Landroid/text/Layout$Alignment;

    .line 55
    .line 56
    :cond_2
    invoke-static {v2, v1, v3, v4, v0}, Landroid/text/StaticLayout$Builder;->obtain(Ljava/lang/CharSequence;IILandroid/text/TextPaint;I)Landroid/text/StaticLayout$Builder;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    iget-object v1, p0, Lrq/g;->e:Landroid/text/Layout$Alignment;

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Landroid/text/StaticLayout$Builder;->setAlignment(Landroid/text/Layout$Alignment;)Landroid/text/StaticLayout$Builder;

    .line 63
    .line 64
    .line 65
    iget-boolean v1, p0, Lrq/g;->j:Z

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Landroid/text/StaticLayout$Builder;->setIncludePad(Z)Landroid/text/StaticLayout$Builder;

    .line 68
    .line 69
    .line 70
    iget-boolean v1, p0, Lrq/g;->k:Z

    .line 71
    .line 72
    if-eqz v1, :cond_3

    .line 73
    .line 74
    sget-object v1, Landroid/text/TextDirectionHeuristics;->RTL:Landroid/text/TextDirectionHeuristic;

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    sget-object v1, Landroid/text/TextDirectionHeuristics;->LTR:Landroid/text/TextDirectionHeuristic;

    .line 78
    .line 79
    :goto_0
    invoke-virtual {v0, v1}, Landroid/text/StaticLayout$Builder;->setTextDirection(Landroid/text/TextDirectionHeuristic;)Landroid/text/StaticLayout$Builder;

    .line 80
    .line 81
    .line 82
    iget-object v1, p0, Lrq/g;->l:Landroid/text/TextUtils$TruncateAt;

    .line 83
    .line 84
    if-eqz v1, :cond_4

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Landroid/text/StaticLayout$Builder;->setEllipsize(Landroid/text/TextUtils$TruncateAt;)Landroid/text/StaticLayout$Builder;

    .line 87
    .line 88
    .line 89
    :cond_4
    iget v1, p0, Lrq/g;->f:I

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Landroid/text/StaticLayout$Builder;->setMaxLines(I)Landroid/text/StaticLayout$Builder;

    .line 92
    .line 93
    .line 94
    iget v1, p0, Lrq/g;->g:F

    .line 95
    .line 96
    const/4 v2, 0x0

    .line 97
    cmpl-float v2, v1, v2

    .line 98
    .line 99
    if-nez v2, :cond_5

    .line 100
    .line 101
    iget v2, p0, Lrq/g;->h:F

    .line 102
    .line 103
    const/high16 v3, 0x3f800000    # 1.0f

    .line 104
    .line 105
    cmpl-float v2, v2, v3

    .line 106
    .line 107
    if-eqz v2, :cond_6

    .line 108
    .line 109
    :cond_5
    iget v2, p0, Lrq/g;->h:F

    .line 110
    .line 111
    invoke-virtual {v0, v1, v2}, Landroid/text/StaticLayout$Builder;->setLineSpacing(FF)Landroid/text/StaticLayout$Builder;

    .line 112
    .line 113
    .line 114
    :cond_6
    iget v1, p0, Lrq/g;->f:I

    .line 115
    .line 116
    if-le v1, v5, :cond_7

    .line 117
    .line 118
    iget v1, p0, Lrq/g;->i:I

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Landroid/text/StaticLayout$Builder;->setHyphenationFrequency(I)Landroid/text/StaticLayout$Builder;

    .line 121
    .line 122
    .line 123
    :cond_7
    iget-object p0, p0, Lrq/g;->m:Lrx/b;

    .line 124
    .line 125
    if-eqz p0, :cond_8

    .line 126
    .line 127
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast p0, Lcom/google/android/material/textfield/TextInputLayout;

    .line 130
    .line 131
    iget-object p0, p0, Lcom/google/android/material/textfield/TextInputLayout;->x:Lm/x0;

    .line 132
    .line 133
    invoke-virtual {p0}, Landroid/widget/TextView;->getBreakStrategy()I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    invoke-virtual {v0, p0}, Landroid/text/StaticLayout$Builder;->setBreakStrategy(I)Landroid/text/StaticLayout$Builder;

    .line 138
    .line 139
    .line 140
    :cond_8
    invoke-virtual {v0}, Landroid/text/StaticLayout$Builder;->build()Landroid/text/StaticLayout;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    return-object p0
.end method
