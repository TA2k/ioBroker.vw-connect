.class public final synthetic La71/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, La71/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, La71/y;->e:Z

    iput-boolean p2, p0, La71/y;->f:Z

    iput-object p3, p0, La71/y;->g:Lay0/a;

    iput-object p4, p0, La71/y;->h:Ljava/lang/Object;

    iput-object p5, p0, La71/y;->i:Ljava/lang/Object;

    iput-object p6, p0, La71/y;->j:Ljava/lang/Object;

    iput-object p7, p0, La71/y;->k:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ZZLay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 2
    const/4 p8, 0x1

    iput p8, p0, La71/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, La71/y;->e:Z

    iput-boolean p2, p0, La71/y;->f:Z

    iput-object p3, p0, La71/y;->g:Lay0/a;

    iput-object p4, p0, La71/y;->h:Ljava/lang/Object;

    iput-object p5, p0, La71/y;->i:Ljava/lang/Object;

    iput-object p6, p0, La71/y;->j:Ljava/lang/Object;

    iput-object p7, p0, La71/y;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, La71/y;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La71/y;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v4, v0

    .line 9
    check-cast v4, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, La71/y;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v5, v0

    .line 14
    check-cast v5, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, p0, La71/y;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v6, v0

    .line 19
    check-cast v6, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v0, p0, La71/y;->k:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v7, v0

    .line 24
    check-cast v7, Ljava/lang/String;

    .line 25
    .line 26
    move-object v8, p1

    .line 27
    check-cast v8, Ll2/o;

    .line 28
    .line 29
    check-cast p2, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/4 p1, 0x1

    .line 35
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result v9

    .line 39
    iget-boolean v1, p0, La71/y;->e:Z

    .line 40
    .line 41
    iget-boolean v2, p0, La71/y;->f:Z

    .line 42
    .line 43
    iget-object v3, p0, La71/y;->g:Lay0/a;

    .line 44
    .line 45
    invoke-static/range {v1 .. v9}, Ls60/a;->i(ZZLay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 46
    .line 47
    .line 48
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    iget-object v0, p0, La71/y;->h:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v5, v0

    .line 54
    check-cast v5, Lay0/a;

    .line 55
    .line 56
    iget-object v0, p0, La71/y;->i:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v6, v0

    .line 59
    check-cast v6, Lay0/a;

    .line 60
    .line 61
    iget-object v0, p0, La71/y;->j:Ljava/lang/Object;

    .line 62
    .line 63
    move-object v7, v0

    .line 64
    check-cast v7, Lay0/a;

    .line 65
    .line 66
    iget-object v0, p0, La71/y;->k:Ljava/lang/Object;

    .line 67
    .line 68
    move-object v8, v0

    .line 69
    check-cast v8, Lay0/a;

    .line 70
    .line 71
    check-cast p1, Ll2/o;

    .line 72
    .line 73
    check-cast p2, Ljava/lang/Integer;

    .line 74
    .line 75
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    and-int/lit8 v0, p2, 0x3

    .line 80
    .line 81
    const/4 v1, 0x2

    .line 82
    const/4 v2, 0x1

    .line 83
    if-eq v0, v1, :cond_0

    .line 84
    .line 85
    move v0, v2

    .line 86
    goto :goto_0

    .line 87
    :cond_0
    const/4 v0, 0x0

    .line 88
    :goto_0
    and-int/2addr p2, v2

    .line 89
    move-object v9, p1

    .line 90
    check-cast v9, Ll2/t;

    .line 91
    .line 92
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-eqz p1, :cond_1

    .line 97
    .line 98
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 99
    .line 100
    const/4 v10, 0x6

    .line 101
    iget-boolean v2, p0, La71/y;->e:Z

    .line 102
    .line 103
    iget-boolean v3, p0, La71/y;->f:Z

    .line 104
    .line 105
    iget-object v4, p0, La71/y;->g:Lay0/a;

    .line 106
    .line 107
    invoke-static/range {v1 .. v10}, La71/b;->h(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_1
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 112
    .line 113
    .line 114
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
