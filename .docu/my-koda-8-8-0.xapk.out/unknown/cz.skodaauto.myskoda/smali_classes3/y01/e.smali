.class public final Ly01/e;
.super Ly01/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ly01/e;->b:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(ILjava/io/StringWriter;)Z
    .locals 4

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-lt p1, v0, :cond_0

    .line 5
    .line 6
    iget p0, p0, Ly01/e;->b:I

    .line 7
    .line 8
    if-gt p1, p0, :cond_0

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    const p0, 0xffff

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    const-string v2, "\\u"

    .line 16
    .line 17
    if-le p1, p0, :cond_1

    .line 18
    .line 19
    invoke-static {p1}, Ljava/lang/Character;->toChars(I)[C

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    new-instance p1, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    aget-char v1, p0, v1

    .line 29
    .line 30
    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    sget-object v3, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 35
    .line 36
    invoke-virtual {v1, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    aget-char p0, p0, v0

    .line 47
    .line 48
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {p0, v3}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return v0

    .line 67
    :cond_1
    invoke-virtual {p2, v2}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    shr-int/lit8 p0, p1, 0xc

    .line 71
    .line 72
    and-int/lit8 p0, p0, 0xf

    .line 73
    .line 74
    sget-object v1, Ly01/b;->a:[C

    .line 75
    .line 76
    aget-char p0, v1, p0

    .line 77
    .line 78
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(I)V

    .line 79
    .line 80
    .line 81
    shr-int/lit8 p0, p1, 0x8

    .line 82
    .line 83
    and-int/lit8 p0, p0, 0xf

    .line 84
    .line 85
    aget-char p0, v1, p0

    .line 86
    .line 87
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(I)V

    .line 88
    .line 89
    .line 90
    shr-int/lit8 p0, p1, 0x4

    .line 91
    .line 92
    and-int/lit8 p0, p0, 0xf

    .line 93
    .line 94
    aget-char p0, v1, p0

    .line 95
    .line 96
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(I)V

    .line 97
    .line 98
    .line 99
    and-int/lit8 p0, p1, 0xf

    .line 100
    .line 101
    aget-char p0, v1, p0

    .line 102
    .line 103
    invoke-virtual {p2, p0}, Ljava/io/Writer;->write(I)V

    .line 104
    .line 105
    .line 106
    return v0
.end method
