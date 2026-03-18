.class public final Ly01/f;
.super Ly01/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Ljava/util/HashMap;

.field public final c:Ljava/util/BitSet;

.field public final d:I

.field public final e:I


# direct methods
.method public constructor <init>(Ljava/util/Map;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_3

    .line 5
    .line 6
    new-instance v0, Ljava/util/HashMap;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ly01/f;->b:Ljava/util/HashMap;

    .line 12
    .line 13
    new-instance v0, Ljava/util/BitSet;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/BitSet;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ly01/f;->c:Ljava/util/BitSet;

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const/4 v0, 0x0

    .line 29
    const v1, 0x7fffffff

    .line 30
    .line 31
    .line 32
    move v2, v0

    .line 33
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Ljava/util/Map$Entry;

    .line 44
    .line 45
    iget-object v4, p0, Ly01/f;->b:Ljava/util/HashMap;

    .line 46
    .line 47
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    check-cast v5, Ljava/lang/CharSequence;

    .line 52
    .line 53
    invoke-interface {v5}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    check-cast v6, Ljava/lang/CharSequence;

    .line 62
    .line 63
    invoke-interface {v6}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    invoke-virtual {v4, v5, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    iget-object v4, p0, Ly01/f;->c:Ljava/util/BitSet;

    .line 71
    .line 72
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    check-cast v5, Ljava/lang/CharSequence;

    .line 77
    .line 78
    invoke-interface {v5, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    invoke-virtual {v4, v5}, Ljava/util/BitSet;->set(I)V

    .line 83
    .line 84
    .line 85
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    check-cast v3, Ljava/lang/CharSequence;

    .line 90
    .line 91
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    if-ge v3, v1, :cond_1

    .line 96
    .line 97
    move v1, v3

    .line 98
    :cond_1
    if-le v3, v2, :cond_0

    .line 99
    .line 100
    move v2, v3

    .line 101
    goto :goto_0

    .line 102
    :cond_2
    iput v1, p0, Ly01/f;->d:I

    .line 103
    .line 104
    iput v2, p0, Ly01/f;->e:I

    .line 105
    .line 106
    return-void

    .line 107
    :cond_3
    new-instance p0, Ljava/security/InvalidParameterException;

    .line 108
    .line 109
    const-string p1, "lookupMap cannot be null"

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/security/InvalidParameterException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;ILjava/io/StringWriter;)I
    .locals 5

    .line 1
    iget-object v0, p0, Ly01/f;->c:Ljava/util/BitSet;

    .line 2
    .line 3
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {v0, v1}, Ljava/util/BitSet;->get(I)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    iget v0, p0, Ly01/f;->e:I

    .line 15
    .line 16
    add-int v2, p2, v0

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-le v2, v3, :cond_0

    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    sub-int/2addr v0, p2

    .line 29
    :cond_0
    :goto_0
    iget v2, p0, Ly01/f;->d:I

    .line 30
    .line 31
    if-lt v0, v2, :cond_2

    .line 32
    .line 33
    add-int v2, p2, v0

    .line 34
    .line 35
    invoke-virtual {p1, p2, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    iget-object v3, p0, Ly01/f;->b:Ljava/util/HashMap;

    .line 40
    .line 41
    invoke-interface {v2}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    check-cast v3, Ljava/lang/String;

    .line 50
    .line 51
    if-eqz v3, :cond_1

    .line 52
    .line 53
    invoke-virtual {p3, v3}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    invoke-static {v2, v1, p0}, Ljava/lang/Character;->codePointCount(Ljava/lang/CharSequence;II)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    return p0

    .line 65
    :cond_1
    add-int/lit8 v0, v0, -0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    return v1
.end method
