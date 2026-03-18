.class public final Lgr/c;
.super Lgr/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:C


# direct methods
.method public constructor <init>(C)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-char p1, p0, Lgr/c;->d:C

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(C)Z
    .locals 0

    .line 1
    iget-char p0, p0, Lgr/c;->d:C

    .line 2
    .line 3
    if-ne p1, p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 7

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CharMatcher.is(\'"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x6

    .line 9
    new-array v1, v1, [C

    .line 10
    .line 11
    const/16 v2, 0x5c

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    aput-char v2, v1, v3

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    const/16 v4, 0x75

    .line 18
    .line 19
    aput-char v4, v1, v2

    .line 20
    .line 21
    const/4 v2, 0x2

    .line 22
    aput-char v3, v1, v2

    .line 23
    .line 24
    const/4 v2, 0x3

    .line 25
    aput-char v3, v1, v2

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    aput-char v3, v1, v2

    .line 29
    .line 30
    const/4 v4, 0x5

    .line 31
    aput-char v3, v1, v4

    .line 32
    .line 33
    iget-char p0, p0, Lgr/c;->d:C

    .line 34
    .line 35
    :goto_0
    if-ge v3, v2, :cond_0

    .line 36
    .line 37
    rsub-int/lit8 v4, v3, 0x5

    .line 38
    .line 39
    and-int/lit8 v5, p0, 0xf

    .line 40
    .line 41
    const-string v6, "0123456789ABCDEF"

    .line 42
    .line 43
    invoke-virtual {v6, v5}, Ljava/lang/String;->charAt(I)C

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    aput-char v5, v1, v4

    .line 48
    .line 49
    shr-int/2addr p0, v2

    .line 50
    int-to-char p0, p0

    .line 51
    add-int/lit8 v3, v3, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-static {v1}, Ljava/lang/String;->copyValueOf([C)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string p0, "\')"

    .line 62
    .line 63
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method
