.class public final Lb6/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Ljava/lang/String;

.field public static final c:Ljava/lang/String;

.field public static final d:Lb6/b;

.field public static final e:Lb6/b;


# instance fields
.field public final a:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lb6/g;->c:Lb6/f;

    .line 2
    .line 3
    const/16 v0, 0x200e

    .line 4
    .line 5
    invoke-static {v0}, Ljava/lang/Character;->toString(C)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lb6/b;->b:Ljava/lang/String;

    .line 10
    .line 11
    const/16 v0, 0x200f

    .line 12
    .line 13
    invoke-static {v0}, Ljava/lang/Character;->toString(C)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lb6/b;->c:Ljava/lang/String;

    .line 18
    .line 19
    new-instance v0, Lb6/b;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, v1}, Lb6/b;-><init>(Z)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lb6/b;->d:Lb6/b;

    .line 26
    .line 27
    new-instance v0, Lb6/b;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-direct {v0, v1}, Lb6/b;-><init>(Z)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lb6/b;->e:Lb6/b;

    .line 34
    .line 35
    return-void
.end method

.method public constructor <init>(Z)V
    .locals 1

    .line 1
    sget-object v0, Lb6/g;->a:Lb6/f;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-boolean p1, p0, Lb6/b;->a:Z

    .line 7
    .line 8
    return-void
.end method

.method public static a(Ljava/lang/CharSequence;)I
    .locals 9

    .line 1
    new-instance v0, Lb6/a;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lb6/a;-><init>(Ljava/lang/CharSequence;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    iput p0, v0, Lb6/a;->c:I

    .line 8
    .line 9
    move v1, p0

    .line 10
    move v2, v1

    .line 11
    move v3, v2

    .line 12
    :cond_0
    :goto_0
    iget v4, v0, Lb6/a;->c:I

    .line 13
    .line 14
    iget v5, v0, Lb6/a;->b:I

    .line 15
    .line 16
    const/4 v6, -0x1

    .line 17
    const/4 v7, 0x1

    .line 18
    if-ge v4, v5, :cond_6

    .line 19
    .line 20
    if-nez v1, :cond_6

    .line 21
    .line 22
    iget-object v5, v0, Lb6/a;->a:Ljava/lang/CharSequence;

    .line 23
    .line 24
    invoke-interface {v5, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    iput-char v4, v0, Lb6/a;->d:C

    .line 29
    .line 30
    invoke-static {v4}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-eqz v4, :cond_1

    .line 35
    .line 36
    iget v4, v0, Lb6/a;->c:I

    .line 37
    .line 38
    invoke-static {v5, v4}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    iget v5, v0, Lb6/a;->c:I

    .line 43
    .line 44
    invoke-static {v4}, Ljava/lang/Character;->charCount(I)I

    .line 45
    .line 46
    .line 47
    move-result v8

    .line 48
    add-int/2addr v8, v5

    .line 49
    iput v8, v0, Lb6/a;->c:I

    .line 50
    .line 51
    invoke-static {v4}, Ljava/lang/Character;->getDirectionality(I)B

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    iget v4, v0, Lb6/a;->c:I

    .line 57
    .line 58
    add-int/2addr v4, v7

    .line 59
    iput v4, v0, Lb6/a;->c:I

    .line 60
    .line 61
    iget-char v4, v0, Lb6/a;->d:C

    .line 62
    .line 63
    const/16 v5, 0x700

    .line 64
    .line 65
    if-ge v4, v5, :cond_2

    .line 66
    .line 67
    sget-object v5, Lb6/a;->e:[B

    .line 68
    .line 69
    aget-byte v4, v5, v4

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    invoke-static {v4}, Ljava/lang/Character;->getDirectionality(C)B

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    :goto_1
    if-eqz v4, :cond_4

    .line 77
    .line 78
    if-eq v4, v7, :cond_3

    .line 79
    .line 80
    const/4 v5, 0x2

    .line 81
    if-eq v4, v5, :cond_3

    .line 82
    .line 83
    const/16 v5, 0x9

    .line 84
    .line 85
    if-eq v4, v5, :cond_0

    .line 86
    .line 87
    packed-switch v4, :pswitch_data_0

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :pswitch_0
    add-int/lit8 v3, v3, -0x1

    .line 92
    .line 93
    move v2, p0

    .line 94
    goto :goto_0

    .line 95
    :pswitch_1
    add-int/lit8 v3, v3, 0x1

    .line 96
    .line 97
    move v2, v7

    .line 98
    goto :goto_0

    .line 99
    :pswitch_2
    add-int/lit8 v3, v3, 0x1

    .line 100
    .line 101
    move v2, v6

    .line 102
    goto :goto_0

    .line 103
    :cond_3
    if-nez v3, :cond_5

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_4
    if-nez v3, :cond_5

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_5
    :goto_2
    move v1, v3

    .line 110
    goto :goto_0

    .line 111
    :cond_6
    if-nez v1, :cond_7

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_7
    if-eqz v2, :cond_8

    .line 115
    .line 116
    return v2

    .line 117
    :cond_8
    :goto_3
    iget v2, v0, Lb6/a;->c:I

    .line 118
    .line 119
    if-lez v2, :cond_a

    .line 120
    .line 121
    invoke-virtual {v0}, Lb6/a;->a()B

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    packed-switch v2, :pswitch_data_1

    .line 126
    .line 127
    .line 128
    goto :goto_3

    .line 129
    :pswitch_3
    add-int/lit8 v3, v3, 0x1

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :pswitch_4
    if-ne v1, v3, :cond_9

    .line 133
    .line 134
    :goto_4
    return v7

    .line 135
    :cond_9
    add-int/lit8 v3, v3, -0x1

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :pswitch_5
    if-ne v1, v3, :cond_9

    .line 139
    .line 140
    :goto_5
    return v6

    .line 141
    :cond_a
    :goto_6
    return p0

    .line 142
    nop

    .line 143
    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    :pswitch_data_1
    .packed-switch 0xe
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_4
        :pswitch_3
    .end packed-switch
.end method

.method public static b(Ljava/lang/CharSequence;)I
    .locals 6

    .line 1
    new-instance v0, Lb6/a;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lb6/a;-><init>(Ljava/lang/CharSequence;)V

    .line 4
    .line 5
    .line 6
    iget p0, v0, Lb6/a;->b:I

    .line 7
    .line 8
    iput p0, v0, Lb6/a;->c:I

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    move v1, p0

    .line 12
    :goto_0
    move v2, v1

    .line 13
    :cond_0
    :goto_1
    iget v3, v0, Lb6/a;->c:I

    .line 14
    .line 15
    if-lez v3, :cond_6

    .line 16
    .line 17
    invoke-virtual {v0}, Lb6/a;->a()B

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_4

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v3, v4, :cond_2

    .line 25
    .line 26
    const/4 v5, 0x2

    .line 27
    if-eq v3, v5, :cond_2

    .line 28
    .line 29
    const/16 v5, 0x9

    .line 30
    .line 31
    if-eq v3, v5, :cond_0

    .line 32
    .line 33
    packed-switch v3, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    if-nez v2, :cond_0

    .line 37
    .line 38
    goto :goto_4

    .line 39
    :pswitch_0
    add-int/lit8 v1, v1, 0x1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :pswitch_1
    if-ne v2, v1, :cond_1

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_1
    add-int/lit8 v1, v1, -0x1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :pswitch_2
    if-ne v2, v1, :cond_1

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_2
    if-nez v1, :cond_3

    .line 52
    .line 53
    :goto_2
    return v4

    .line 54
    :cond_3
    if-nez v2, :cond_0

    .line 55
    .line 56
    goto :goto_4

    .line 57
    :cond_4
    if-nez v1, :cond_5

    .line 58
    .line 59
    :goto_3
    const/4 p0, -0x1

    .line 60
    return p0

    .line 61
    :cond_5
    if-nez v2, :cond_0

    .line 62
    .line 63
    :goto_4
    goto :goto_0

    .line 64
    :cond_6
    return p0

    .line 65
    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final c(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;
    .locals 9

    .line 1
    sget-object v0, Lb6/g;->c:Lb6/f;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {v0, v1, p1}, Lb6/f;->n(ILjava/lang/CharSequence;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    new-instance v1, Landroid/text/SpannableStringBuilder;

    .line 16
    .line 17
    invoke-direct {v1}, Landroid/text/SpannableStringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    sget-object v2, Lb6/g;->b:Lb6/f;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    sget-object v2, Lb6/g;->a:Lb6/f;

    .line 26
    .line 27
    :goto_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-virtual {v2, v3, p1}, Lb6/f;->n(ILjava/lang/CharSequence;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    const-string v3, ""

    .line 36
    .line 37
    sget-object v4, Lb6/b;->c:Ljava/lang/String;

    .line 38
    .line 39
    const/4 v5, -0x1

    .line 40
    sget-object v6, Lb6/b;->b:Ljava/lang/String;

    .line 41
    .line 42
    const/4 v7, 0x1

    .line 43
    iget-boolean p0, p0, Lb6/b;->a:Z

    .line 44
    .line 45
    if-nez p0, :cond_3

    .line 46
    .line 47
    if-nez v2, :cond_2

    .line 48
    .line 49
    invoke-static {p1}, Lb6/b;->a(Ljava/lang/CharSequence;)I

    .line 50
    .line 51
    .line 52
    move-result v8

    .line 53
    if-ne v8, v7, :cond_3

    .line 54
    .line 55
    :cond_2
    move-object v2, v6

    .line 56
    goto :goto_1

    .line 57
    :cond_3
    if-eqz p0, :cond_5

    .line 58
    .line 59
    if-eqz v2, :cond_4

    .line 60
    .line 61
    invoke-static {p1}, Lb6/b;->a(Ljava/lang/CharSequence;)I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-ne v2, v5, :cond_5

    .line 66
    .line 67
    :cond_4
    move-object v2, v4

    .line 68
    goto :goto_1

    .line 69
    :cond_5
    move-object v2, v3

    .line 70
    :goto_1
    invoke-virtual {v1, v2}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 71
    .line 72
    .line 73
    if-eq v0, p0, :cond_7

    .line 74
    .line 75
    if-eqz v0, :cond_6

    .line 76
    .line 77
    const/16 v2, 0x202b

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_6
    const/16 v2, 0x202a

    .line 81
    .line 82
    :goto_2
    invoke-virtual {v1, v2}, Landroid/text/SpannableStringBuilder;->append(C)Landroid/text/SpannableStringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1, p1}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 86
    .line 87
    .line 88
    const/16 v2, 0x202c

    .line 89
    .line 90
    invoke-virtual {v1, v2}, Landroid/text/SpannableStringBuilder;->append(C)Landroid/text/SpannableStringBuilder;

    .line 91
    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_7
    invoke-virtual {v1, p1}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 95
    .line 96
    .line 97
    :goto_3
    if-eqz v0, :cond_8

    .line 98
    .line 99
    sget-object v0, Lb6/g;->b:Lb6/f;

    .line 100
    .line 101
    goto :goto_4

    .line 102
    :cond_8
    sget-object v0, Lb6/g;->a:Lb6/f;

    .line 103
    .line 104
    :goto_4
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    invoke-virtual {v0, v2, p1}, Lb6/f;->n(ILjava/lang/CharSequence;)Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-nez p0, :cond_a

    .line 113
    .line 114
    if-nez v0, :cond_9

    .line 115
    .line 116
    invoke-static {p1}, Lb6/b;->b(Ljava/lang/CharSequence;)I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    if-ne v2, v7, :cond_a

    .line 121
    .line 122
    :cond_9
    move-object v3, v6

    .line 123
    goto :goto_5

    .line 124
    :cond_a
    if-eqz p0, :cond_c

    .line 125
    .line 126
    if-eqz v0, :cond_b

    .line 127
    .line 128
    invoke-static {p1}, Lb6/b;->b(Ljava/lang/CharSequence;)I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    if-ne p0, v5, :cond_c

    .line 133
    .line 134
    :cond_b
    move-object v3, v4

    .line 135
    :cond_c
    :goto_5
    invoke-virtual {v1, v3}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 136
    .line 137
    .line 138
    return-object v1
.end method
