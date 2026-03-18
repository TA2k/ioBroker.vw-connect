.class public final Llz0/b;
.super Llz0/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I

.field public final d:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Llz0/b;->c:I

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    const-string v1, "the predefined string "

    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {p0, v0, v1}, Llz0/d;-><init>(Ljava/lang/Integer;Ljava/lang/String;)V

    .line 2
    iput-object p1, p0, Llz0/b;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljz0/r;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llz0/b;->c:I

    const-string v0, "setter"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 3
    invoke-direct {p0, v0, p2}, Llz0/d;-><init>(Ljava/lang/Integer;Ljava/lang/String;)V

    .line 4
    iput-object p1, p0, Llz0/b;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/CharSequence;II)Llz0/f;
    .locals 4

    .line 1
    iget v0, p0, Llz0/b;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "input"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sub-int v0, p4, p3

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    if-ge v0, v1, :cond_0

    .line 15
    .line 16
    new-instance p0, Lc1/l2;

    .line 17
    .line 18
    const/4 p1, 0x4

    .line 19
    invoke-direct {p0, v1, p1}, Lc1/l2;-><init>(II)V

    .line 20
    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    const/16 v1, 0x9

    .line 24
    .line 25
    if-le v0, v1, :cond_1

    .line 26
    .line 27
    new-instance p0, Lc1/l2;

    .line 28
    .line 29
    const/4 p1, 0x5

    .line 30
    invoke-direct {p0, v1, p1}, Lc1/l2;-><init>(II)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    iget-object p0, p0, Llz0/b;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Llz0/a;

    .line 37
    .line 38
    new-instance v1, Liz0/a;

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    :goto_0
    if-ge p3, p4, :cond_2

    .line 42
    .line 43
    invoke-interface {p2, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    mul-int/lit8 v2, v2, 0xa

    .line 48
    .line 49
    add-int/lit8 v3, v3, -0x30

    .line 50
    .line 51
    add-int/2addr v2, v3

    .line 52
    add-int/lit8 p3, p3, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    invoke-direct {v1, v2, v0}, Liz0/a;-><init>(II)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p0, p1, v1}, Llz0/a;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    if-nez p0, :cond_3

    .line 63
    .line 64
    const/4 p0, 0x0

    .line 65
    goto :goto_1

    .line 66
    :cond_3
    new-instance p1, Ld8/c;

    .line 67
    .line 68
    invoke-direct {p1, p0}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    move-object p0, p1

    .line 72
    :goto_1
    return-object p0

    .line 73
    :pswitch_0
    const-string p1, "input"

    .line 74
    .line 75
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-interface {p2, p3, p4}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    iget-object p0, p0, Llz0/b;->d:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast p0, Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    if-eqz p1, :cond_4

    .line 95
    .line 96
    const/4 p0, 0x0

    .line 97
    goto :goto_2

    .line 98
    :cond_4
    new-instance p1, Les/a;

    .line 99
    .line 100
    invoke-direct {p1, p0}, Les/a;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    move-object p0, p1

    .line 104
    :goto_2
    return-object p0

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
