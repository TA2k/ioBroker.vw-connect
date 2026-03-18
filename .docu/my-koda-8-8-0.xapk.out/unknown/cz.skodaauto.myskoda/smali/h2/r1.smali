.class public final synthetic Lh2/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Li2/e0;

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Li2/z;

.field public final synthetic h:Ljava/util/Locale;

.field public final synthetic i:Lh2/y1;

.field public final synthetic j:I

.field public final synthetic k:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Li2/e0;Ll2/b1;Lay0/k;Li2/z;Ljava/util/Locale;Lh2/y1;ILl2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/r1;->d:Li2/e0;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/r1;->e:Ll2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/r1;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/r1;->g:Li2/z;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/r1;->h:Ljava/util/Locale;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/r1;->i:Lh2/y1;

    .line 15
    .line 16
    iput p7, p0, Lh2/r1;->j:I

    .line 17
    .line 18
    iput-object p8, p0, Lh2/r1;->k:Ll2/b1;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Ll4/v;

    .line 2
    .line 3
    iget-object v0, p1, Ll4/v;->a:Lg4/g;

    .line 4
    .line 5
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget-object v2, p0, Lh2/r1;->d:Li2/e0;

    .line 12
    .line 13
    iget-object v2, v2, Li2/e0;->c:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-gt v1, v3, :cond_5

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    :goto_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ge v1, v3, :cond_1

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    invoke-static {v3}, Ljava/lang/Character;->isDigit(C)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-nez v3, :cond_0

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    iget-object v1, p0, Lh2/r1;->k:Ll2/b1;

    .line 43
    .line 44
    invoke-interface {v1, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-object v1, p0, Lh2/r1;->e:Ll2/b1;

    .line 60
    .line 61
    iget-object v3, p0, Lh2/r1;->f:Lay0/k;

    .line 62
    .line 63
    const/4 v4, 0x0

    .line 64
    if-nez v0, :cond_2

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    if-ge v0, v5, :cond_3

    .line 76
    .line 77
    :goto_1
    const-string p0, ""

    .line 78
    .line 79
    invoke-interface {v1, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    invoke-interface {v3, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    iget-object v0, p0, Lh2/r1;->g:Li2/z;

    .line 87
    .line 88
    iget-object v5, p0, Lh2/r1;->h:Ljava/util/Locale;

    .line 89
    .line 90
    invoke-virtual {v0, p1, v2, v5}, Li2/z;->d(Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)Li2/y;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    iget-object v0, p0, Lh2/r1;->i:Lh2/y1;

    .line 95
    .line 96
    iget p0, p0, Lh2/r1;->j:I

    .line 97
    .line 98
    invoke-virtual {v0, p1, p0, v5}, Lh2/y1;->a(Li2/y;ILjava/util/Locale;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-interface {v1, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    check-cast p0, Ljava/lang/CharSequence;

    .line 110
    .line 111
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-nez p0, :cond_4

    .line 116
    .line 117
    if-eqz p1, :cond_4

    .line 118
    .line 119
    iget-wide p0, p1, Li2/y;->g:J

    .line 120
    .line 121
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    :cond_4
    invoke-interface {v3, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    :cond_5
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    return-object p0
.end method
