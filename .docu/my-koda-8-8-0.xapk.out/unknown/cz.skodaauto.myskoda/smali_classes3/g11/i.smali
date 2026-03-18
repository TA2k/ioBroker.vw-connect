.class public final Lg11/i;
.super Ll11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Lj11/a;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lg11/i;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lj11/n;

    .line 3
    invoke-direct {v0}, Lj11/s;-><init>()V

    .line 4
    iput-object v0, p0, Lg11/i;->b:Lj11/a;

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lg11/i;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(ILbn/c;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lg11/i;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    new-instance v0, Lj11/j;

    .line 8
    invoke-direct {v0}, Lj11/s;-><init>()V

    .line 9
    iput-object v0, p0, Lg11/i;->b:Lj11/a;

    .line 10
    iput p1, v0, Lj11/j;->g:I

    .line 11
    iput-object p2, p0, Lg11/i;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Lk11/b;)V
    .locals 1

    .line 1
    iget v0, p0, Lg11/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lg11/i;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/util/ArrayList;

    .line 10
    .line 11
    iget-object p1, p1, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public e()V
    .locals 10

    .line 1
    iget v0, p0, Lg11/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object v0, p0, Lg11/i;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x1

    .line 16
    sub-int/2addr v1, v2

    .line 17
    :goto_0
    const/4 v3, 0x0

    .line 18
    if-ltz v1, :cond_4

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Ljava/lang/CharSequence;

    .line 25
    .line 26
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    move v6, v3

    .line 31
    :goto_1
    const/4 v7, -0x1

    .line 32
    if-ge v6, v5, :cond_1

    .line 33
    .line 34
    invoke-interface {v4, v6}, Ljava/lang/CharSequence;->charAt(I)C

    .line 35
    .line 36
    .line 37
    move-result v8

    .line 38
    const/16 v9, 0x20

    .line 39
    .line 40
    if-eq v8, v9, :cond_0

    .line 41
    .line 42
    packed-switch v8, :pswitch_data_1

    .line 43
    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_0
    :pswitch_1
    add-int/lit8 v6, v6, 0x1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v6, v7

    .line 50
    :goto_2
    if-ne v6, v7, :cond_2

    .line 51
    .line 52
    move v4, v2

    .line 53
    goto :goto_3

    .line 54
    :cond_2
    move v4, v3

    .line 55
    :goto_3
    if-nez v4, :cond_3

    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_3
    add-int/lit8 v1, v1, -0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_4
    :goto_4
    new-instance v4, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 64
    .line 65
    .line 66
    :goto_5
    add-int/lit8 v5, v1, 0x1

    .line 67
    .line 68
    if-ge v3, v5, :cond_5

    .line 69
    .line 70
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    check-cast v5, Ljava/lang/CharSequence;

    .line 75
    .line 76
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    const/16 v5, 0xa

    .line 80
    .line 81
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    add-int/lit8 v3, v3, 0x1

    .line 85
    .line 86
    goto :goto_5

    .line 87
    :cond_5
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    iget-object p0, p0, Lg11/i;->b:Lj11/a;

    .line 92
    .line 93
    check-cast p0, Lj11/n;

    .line 94
    .line 95
    iput-object v0, p0, Lj11/n;->g:Ljava/lang/String;

    .line 96
    .line 97
    return-void

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch

    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    :pswitch_data_1
    .packed-switch 0x9
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch
.end method

.method public final f()Lj11/a;
    .locals 1

    .line 1
    iget v0, p0, Lg11/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg11/i;->b:Lj11/a;

    .line 7
    .line 8
    check-cast p0, Lj11/n;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lg11/i;->b:Lj11/a;

    .line 12
    .line 13
    check-cast p0, Lj11/j;

    .line 14
    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public h(Lg11/l;)V
    .locals 1

    .line 1
    iget v0, p0, Lg11/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object v0, p0, Lg11/i;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lbn/c;

    .line 10
    .line 11
    iget-object p0, p0, Lg11/i;->b:Lj11/a;

    .line 12
    .line 13
    check-cast p0, Lj11/j;

    .line 14
    .line 15
    invoke-virtual {p1, v0, p0}, Lg11/l;->e(Lbn/c;Lj11/s;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Lg11/g;)Lc9/h;
    .locals 2

    .line 1
    iget p0, p0, Lg11/i;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p1, Lg11/g;->h:I

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    if-lt p0, v0, :cond_0

    .line 10
    .line 11
    iget p0, p1, Lg11/g;->d:I

    .line 12
    .line 13
    add-int/2addr p0, v0

    .line 14
    new-instance p1, Lc9/h;

    .line 15
    .line 16
    const/4 v0, -0x1

    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-direct {p1, v0, p0, v1}, Lc9/h;-><init>(IIZ)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-boolean p0, p1, Lg11/g;->i:Z

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    iget p0, p1, Lg11/g;->f:I

    .line 27
    .line 28
    invoke-static {p0}, Lc9/h;->a(I)Lc9/h;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 p1, 0x0

    .line 34
    :goto_0
    return-object p1

    .line 35
    :pswitch_0
    const/4 p0, 0x0

    .line 36
    return-object p0

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
