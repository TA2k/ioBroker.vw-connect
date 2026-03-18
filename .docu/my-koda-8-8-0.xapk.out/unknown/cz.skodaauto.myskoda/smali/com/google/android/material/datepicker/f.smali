.class public abstract Lcom/google/android/material/datepicker/f;
.super Lrq/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lcom/google/android/material/textfield/TextInputLayout;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/text/SimpleDateFormat;

.field public final g:Lcom/google/android/material/datepicker/c;

.field public final h:Ljava/lang/String;

.field public final i:La8/z;

.field public j:Lcom/google/android/material/datepicker/e;

.field public k:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/text/SimpleDateFormat;Lcom/google/android/material/textfield/TextInputLayout;Lcom/google/android/material/datepicker/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/android/material/datepicker/f;->k:I

    .line 6
    .line 7
    iput-object p1, p0, Lcom/google/android/material/datepicker/f;->e:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p2, p0, Lcom/google/android/material/datepicker/f;->f:Ljava/text/SimpleDateFormat;

    .line 10
    .line 11
    iput-object p3, p0, Lcom/google/android/material/datepicker/f;->d:Lcom/google/android/material/textfield/TextInputLayout;

    .line 12
    .line 13
    iput-object p4, p0, Lcom/google/android/material/datepicker/f;->g:Lcom/google/android/material/datepicker/c;

    .line 14
    .line 15
    invoke-virtual {p3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    const p3, 0x7f1207df

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p3}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    iput-object p2, p0, Lcom/google/android/material/datepicker/f;->h:Ljava/lang/String;

    .line 27
    .line 28
    new-instance p2, La8/z;

    .line 29
    .line 30
    const/16 p3, 0x11

    .line 31
    .line 32
    invoke-direct {p2, p3, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iput-object p2, p0, Lcom/google/android/material/datepicker/f;->i:La8/z;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public abstract a()V
.end method

.method public final afterTextChanged(Landroid/text/Editable;)V
    .locals 3

    .line 1
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Ljava/util/Locale;->KOREAN:Ljava/util/Locale;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_2

    .line 27
    .line 28
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object v1, p0, Lcom/google/android/material/datepicker/f;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-ge v0, v2, :cond_2

    .line 39
    .line 40
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget p0, p0, Lcom/google/android/material/datepicker/f;->k:I

    .line 45
    .line 46
    if-ge v0, p0, :cond_1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-virtual {v1, p0}, Ljava/lang/String;->charAt(I)C

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-static {p0}, Ljava/lang/Character;->isLetterOrDigit(C)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-nez v0, :cond_2

    .line 62
    .line 63
    invoke-interface {p1, p0}, Landroid/text/Editable;->append(C)Landroid/text/Editable;

    .line 64
    .line 65
    .line 66
    :cond_2
    :goto_0
    return-void
.end method

.method public abstract b(Ljava/lang/Long;)V
.end method

.method public final beforeTextChanged(Ljava/lang/CharSequence;III)V
    .locals 0

    .line 1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput p1, p0, Lcom/google/android/material/datepicker/f;->k:I

    .line 6
    .line 7
    return-void
.end method

.method public final onTextChanged(Ljava/lang/CharSequence;III)V
    .locals 6

    .line 1
    iget-object p2, p0, Lcom/google/android/material/datepicker/f;->g:Lcom/google/android/material/datepicker/c;

    .line 2
    .line 3
    iget-object p3, p0, Lcom/google/android/material/datepicker/f;->d:Lcom/google/android/material/textfield/TextInputLayout;

    .line 4
    .line 5
    iget-object p4, p0, Lcom/google/android/material/datepicker/f;->i:La8/z;

    .line 6
    .line 7
    invoke-virtual {p3, p4}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lcom/google/android/material/datepicker/f;->j:Lcom/google/android/material/datepicker/e;

    .line 11
    .line 12
    invoke-virtual {p3, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 13
    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    invoke-virtual {p3, v0}, Lcom/google/android/material/textfield/TextInputLayout;->setError(Ljava/lang/CharSequence;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, v0}, Lcom/google/android/material/datepicker/f;->b(Ljava/lang/Long;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_2

    .line 27
    .line 28
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    iget-object v2, p0, Lcom/google/android/material/datepicker/f;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-ge v1, v2, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    :try_start_0
    iget-object v1, p0, Lcom/google/android/material/datepicker/f;->f:Ljava/text/SimpleDateFormat;

    .line 42
    .line 43
    invoke-interface {p1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-virtual {v1, p1}, Ljava/text/DateFormat;->parse(Ljava/lang/String;)Ljava/util/Date;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-virtual {p3, v0}, Lcom/google/android/material/textfield/TextInputLayout;->setError(Ljava/lang/CharSequence;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 55
    .line 56
    .line 57
    move-result-wide v0

    .line 58
    iget-object v2, p2, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 59
    .line 60
    invoke-interface {v2, v0, v1}, Lcom/google/android/material/datepicker/b;->g(J)Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v2, :cond_1

    .line 65
    .line 66
    iget-object v2, p2, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 67
    .line 68
    iget-object v2, v2, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 69
    .line 70
    invoke-static {v2}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    const/4 v3, 0x5

    .line 75
    const/4 v4, 0x1

    .line 76
    invoke-virtual {v2, v3, v4}, Ljava/util/Calendar;->set(II)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v2}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 80
    .line 81
    .line 82
    move-result-wide v4

    .line 83
    cmp-long v2, v4, v0

    .line 84
    .line 85
    if-gtz v2, :cond_1

    .line 86
    .line 87
    iget-object p2, p2, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 88
    .line 89
    iget v2, p2, Lcom/google/android/material/datepicker/b0;->h:I

    .line 90
    .line 91
    iget-object p2, p2, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 92
    .line 93
    invoke-static {p2}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    invoke-virtual {p2, v3, v2}, Ljava/util/Calendar;->set(II)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p2}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 101
    .line 102
    .line 103
    move-result-wide v2

    .line 104
    cmp-long p2, v0, v2

    .line 105
    .line 106
    if-gtz p2, :cond_1

    .line 107
    .line 108
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 109
    .line 110
    .line 111
    move-result-wide p1

    .line 112
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/f;->b(Ljava/lang/Long;)V

    .line 117
    .line 118
    .line 119
    return-void

    .line 120
    :cond_1
    new-instance p1, Lcom/google/android/material/datepicker/e;

    .line 121
    .line 122
    invoke-direct {p1, p0, v0, v1}, Lcom/google/android/material/datepicker/e;-><init>(Lcom/google/android/material/datepicker/f;J)V

    .line 123
    .line 124
    .line 125
    iput-object p1, p0, Lcom/google/android/material/datepicker/f;->j:Lcom/google/android/material/datepicker/e;

    .line 126
    .line 127
    invoke-virtual {p3, p1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z
    :try_end_0
    .catch Ljava/text/ParseException; {:try_start_0 .. :try_end_0} :catch_0

    .line 128
    .line 129
    .line 130
    return-void

    .line 131
    :catch_0
    invoke-virtual {p3, p4}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 132
    .line 133
    .line 134
    :cond_2
    :goto_0
    return-void
.end method
