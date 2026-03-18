.class public final Lhz0/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lhz0/z0;


# instance fields
.field public final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    new-instance v0, Lhz0/z0;

    .line 2
    .line 3
    const-string v11, "November"

    .line 4
    .line 5
    const-string v12, "December"

    .line 6
    .line 7
    const-string v1, "January"

    .line 8
    .line 9
    const-string v2, "February"

    .line 10
    .line 11
    const-string v3, "March"

    .line 12
    .line 13
    const-string v4, "April"

    .line 14
    .line 15
    const-string v5, "May"

    .line 16
    .line 17
    const-string v6, "June"

    .line 18
    .line 19
    const-string v7, "July"

    .line 20
    .line 21
    const-string v8, "August"

    .line 22
    .line 23
    const-string v9, "September"

    .line 24
    .line 25
    const-string v10, "October"

    .line 26
    .line 27
    filled-new-array/range {v1 .. v12}, [Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-direct {v0, v1}, Lhz0/z0;-><init>(Ljava/util/List;)V

    .line 36
    .line 37
    .line 38
    new-instance v0, Lhz0/z0;

    .line 39
    .line 40
    const-string v11, "Nov"

    .line 41
    .line 42
    const-string v12, "Dec"

    .line 43
    .line 44
    const-string v1, "Jan"

    .line 45
    .line 46
    const-string v2, "Feb"

    .line 47
    .line 48
    const-string v3, "Mar"

    .line 49
    .line 50
    const-string v4, "Apr"

    .line 51
    .line 52
    const-string v5, "May"

    .line 53
    .line 54
    const-string v6, "Jun"

    .line 55
    .line 56
    const-string v7, "Jul"

    .line 57
    .line 58
    const-string v8, "Aug"

    .line 59
    .line 60
    const-string v9, "Sep"

    .line 61
    .line 62
    const-string v10, "Oct"

    .line 63
    .line 64
    filled-new-array/range {v1 .. v12}, [Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-direct {v0, v1}, Lhz0/z0;-><init>(Ljava/util/List;)V

    .line 73
    .line 74
    .line 75
    sput-object v0, Lhz0/z0;->b:Lhz0/z0;

    .line 76
    .line 77
    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/16 v1, 0xc

    .line 11
    .line 12
    if-ne v0, v1, :cond_4

    .line 13
    .line 14
    check-cast p1, Ljava/util/Collection;

    .line 15
    .line 16
    invoke-static {p1}, Ljp/k1;->g(Ljava/util/Collection;)Lgy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    :cond_0
    move-object v0, p1

    .line 25
    check-cast v0, Lgy0/i;

    .line 26
    .line 27
    iget-boolean v0, v0, Lgy0/i;->f:Z

    .line 28
    .line 29
    if-eqz v0, :cond_3

    .line 30
    .line 31
    move-object v0, p1

    .line 32
    check-cast v0, Lmx0/w;

    .line 33
    .line 34
    invoke-virtual {v0}, Lmx0/w;->nextInt()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-object v1, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 39
    .line 40
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Ljava/lang/CharSequence;

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-lez v1, :cond_2

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    :goto_0
    if-ge v1, v0, :cond_0

    .line 54
    .line 55
    iget-object v2, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 56
    .line 57
    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    iget-object v3, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 62
    .line 63
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-nez v2, :cond_1

    .line 72
    .line 73
    add-int/lit8 v1, v1, 0x1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v1, "Month names must be unique, but \'"

    .line 79
    .line 80
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iget-object p0, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 84
    .line 85
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    check-cast p0, Ljava/lang/String;

    .line 90
    .line 91
    const-string v0, "\' was repeated"

    .line 92
    .line 93
    invoke-static {p1, p0, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 98
    .line 99
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p1

    .line 107
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 108
    .line 109
    const-string p1, "A month name can not be empty"

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_3
    return-void

    .line 116
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 117
    .line 118
    const-string p1, "Month names must contain exactly 12 elements"

    .line 119
    .line 120
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lhz0/z0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lhz0/z0;

    .line 6
    .line 7
    iget-object p1, p1, Lhz0/z0;->a:Ljava/util/List;

    .line 8
    .line 9
    iget-object p0, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object p0, p0, Lhz0/z0;->a:Ljava/util/List;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Ljava/lang/Iterable;

    .line 5
    .line 6
    sget-object v4, Lhz0/y0;->d:Lhz0/y0;

    .line 7
    .line 8
    const/16 v5, 0x18

    .line 9
    .line 10
    const-string v1, ", "

    .line 11
    .line 12
    const-string v2, "MonthNames("

    .line 13
    .line 14
    const-string v3, ")"

    .line 15
    .line 16
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
