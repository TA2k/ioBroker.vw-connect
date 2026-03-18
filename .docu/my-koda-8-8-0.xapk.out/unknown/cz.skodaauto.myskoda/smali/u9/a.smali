.class public final Lu9/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Ljava/util/regex/Pattern;

.field public static final d:Ljava/util/regex/Pattern;


# instance fields
.field public final a:Lw7/p;

.field public final b:Ljava/lang/StringBuilder;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "\\[voice=\"([^\"]*)\"\\]"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lu9/a;->c:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    const-string v0, "^((?:[0-9]*\\.)?[0-9]+)(px|em|%)$"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lu9/a;->d:Ljava/util/regex/Pattern;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw7/p;

    .line 5
    .line 6
    invoke-direct {v0}, Lw7/p;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lu9/a;->a:Lw7/p;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lu9/a;->b:Ljava/lang/StringBuilder;

    .line 17
    .line 18
    return-void
.end method

.method public static a(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 3
    .line 4
    .line 5
    iget v1, p0, Lw7/p;->b:I

    .line 6
    .line 7
    iget v2, p0, Lw7/p;->c:I

    .line 8
    .line 9
    :goto_0
    if-ge v1, v2, :cond_5

    .line 10
    .line 11
    if-nez v0, :cond_5

    .line 12
    .line 13
    iget-object v3, p0, Lw7/p;->a:[B

    .line 14
    .line 15
    aget-byte v3, v3, v1

    .line 16
    .line 17
    int-to-char v3, v3

    .line 18
    const/16 v4, 0x41

    .line 19
    .line 20
    if-lt v3, v4, :cond_0

    .line 21
    .line 22
    const/16 v4, 0x5a

    .line 23
    .line 24
    if-le v3, v4, :cond_4

    .line 25
    .line 26
    :cond_0
    const/16 v4, 0x61

    .line 27
    .line 28
    if-lt v3, v4, :cond_1

    .line 29
    .line 30
    const/16 v4, 0x7a

    .line 31
    .line 32
    if-le v3, v4, :cond_4

    .line 33
    .line 34
    :cond_1
    const/16 v4, 0x30

    .line 35
    .line 36
    if-lt v3, v4, :cond_2

    .line 37
    .line 38
    const/16 v4, 0x39

    .line 39
    .line 40
    if-le v3, v4, :cond_4

    .line 41
    .line 42
    :cond_2
    const/16 v4, 0x23

    .line 43
    .line 44
    if-eq v3, v4, :cond_4

    .line 45
    .line 46
    const/16 v4, 0x2d

    .line 47
    .line 48
    if-eq v3, v4, :cond_4

    .line 49
    .line 50
    const/16 v4, 0x2e

    .line 51
    .line 52
    if-eq v3, v4, :cond_4

    .line 53
    .line 54
    const/16 v4, 0x5f

    .line 55
    .line 56
    if-ne v3, v4, :cond_3

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    const/4 v0, 0x1

    .line 60
    goto :goto_0

    .line 61
    :cond_4
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 62
    .line 63
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_5
    iget v0, p0, Lw7/p;->b:I

    .line 68
    .line 69
    sub-int/2addr v1, v0

    .line 70
    invoke-virtual {p0, v1}, Lw7/p;->J(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0
.end method

.method public static b(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lu9/a;->c(Lw7/p;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-static {p0, p1}, Lu9/a;->a(Lw7/p;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    return-object p1

    .line 23
    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v0, ""

    .line 26
    .line 27
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lw7/p;->w()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    int-to-char p0, p0

    .line 35
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public static c(Lw7/p;)V
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    :goto_0
    move v1, v0

    .line 3
    :goto_1
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    if-lez v2, :cond_4

    .line 8
    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    iget v1, p0, Lw7/p;->b:I

    .line 12
    .line 13
    iget-object v2, p0, Lw7/p;->a:[B

    .line 14
    .line 15
    aget-byte v3, v2, v1

    .line 16
    .line 17
    int-to-char v4, v3

    .line 18
    const/16 v5, 0x9

    .line 19
    .line 20
    if-eq v4, v5, :cond_3

    .line 21
    .line 22
    const/16 v5, 0xa

    .line 23
    .line 24
    if-eq v4, v5, :cond_3

    .line 25
    .line 26
    const/16 v5, 0xc

    .line 27
    .line 28
    if-eq v4, v5, :cond_3

    .line 29
    .line 30
    const/16 v5, 0xd

    .line 31
    .line 32
    if-eq v4, v5, :cond_3

    .line 33
    .line 34
    const/16 v5, 0x20

    .line 35
    .line 36
    if-eq v4, v5, :cond_3

    .line 37
    .line 38
    iget v4, p0, Lw7/p;->c:I

    .line 39
    .line 40
    add-int/lit8 v5, v1, 0x2

    .line 41
    .line 42
    if-gt v5, v4, :cond_2

    .line 43
    .line 44
    add-int/lit8 v1, v1, 0x1

    .line 45
    .line 46
    const/16 v6, 0x2f

    .line 47
    .line 48
    if-ne v3, v6, :cond_2

    .line 49
    .line 50
    aget-byte v1, v2, v1

    .line 51
    .line 52
    const/16 v3, 0x2a

    .line 53
    .line 54
    if-ne v1, v3, :cond_2

    .line 55
    .line 56
    :goto_2
    add-int/lit8 v1, v5, 0x1

    .line 57
    .line 58
    if-ge v1, v4, :cond_1

    .line 59
    .line 60
    aget-byte v7, v2, v5

    .line 61
    .line 62
    int-to-char v7, v7

    .line 63
    if-ne v7, v3, :cond_0

    .line 64
    .line 65
    aget-byte v7, v2, v1

    .line 66
    .line 67
    int-to-char v7, v7

    .line 68
    if-ne v7, v6, :cond_0

    .line 69
    .line 70
    add-int/lit8 v5, v5, 0x2

    .line 71
    .line 72
    move v4, v5

    .line 73
    goto :goto_2

    .line 74
    :cond_0
    move v5, v1

    .line 75
    goto :goto_2

    .line 76
    :cond_1
    iget v1, p0, Lw7/p;->b:I

    .line 77
    .line 78
    sub-int/2addr v4, v1

    .line 79
    invoke-virtual {p0, v4}, Lw7/p;->J(I)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_2
    const/4 v1, 0x0

    .line 84
    goto :goto_1

    .line 85
    :cond_3
    invoke-virtual {p0, v0}, Lw7/p;->J(I)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_4
    return-void
.end method
