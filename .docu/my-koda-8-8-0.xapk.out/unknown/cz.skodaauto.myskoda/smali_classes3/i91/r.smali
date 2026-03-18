.class public final synthetic Li91/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Llx0/e;

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lay0/a;Lx2/s;ZZI)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/r;->i:Ljava/lang/Object;

    iput-object p2, p0, Li91/r;->g:Llx0/e;

    iput-object p3, p0, Li91/r;->j:Ljava/lang/Object;

    iput-boolean p4, p0, Li91/r;->e:Z

    iput-boolean p5, p0, Li91/r;->f:Z

    iput p6, p0, Li91/r;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;ZZLx2/s;Lay0/k;I)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Li91/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/r;->i:Ljava/lang/Object;

    iput-boolean p2, p0, Li91/r;->e:Z

    iput-boolean p3, p0, Li91/r;->f:Z

    iput-object p4, p0, Li91/r;->j:Ljava/lang/Object;

    iput-object p5, p0, Li91/r;->g:Llx0/e;

    iput p6, p0, Li91/r;->h:I

    return-void
.end method

.method public synthetic constructor <init>(ZZLon0/a0;Lay0/a;Lay0/a;I)V
    .locals 1

    .line 3
    const/4 v0, 0x1

    iput v0, p0, Li91/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Li91/r;->e:Z

    iput-boolean p2, p0, Li91/r;->f:Z

    iput-object p3, p0, Li91/r;->i:Ljava/lang/Object;

    iput-object p4, p0, Li91/r;->g:Llx0/e;

    iput-object p5, p0, Li91/r;->j:Ljava/lang/Object;

    iput p6, p0, Li91/r;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li91/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/r;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/util/List;

    .line 10
    .line 11
    iget-object v0, p0, Li91/r;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lx2/s;

    .line 15
    .line 16
    iget-object v0, p0, Li91/r;->g:Llx0/e;

    .line 17
    .line 18
    move-object v5, v0

    .line 19
    check-cast v5, Lay0/k;

    .line 20
    .line 21
    move-object v6, p1

    .line 22
    check-cast v6, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget p1, p0, Li91/r;->h:I

    .line 30
    .line 31
    or-int/lit8 p1, p1, 0x1

    .line 32
    .line 33
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    iget-boolean v2, p0, Li91/r;->e:Z

    .line 38
    .line 39
    iget-boolean v3, p0, Li91/r;->f:Z

    .line 40
    .line 41
    invoke-static/range {v1 .. v7}, Lxk0/h;->m0(Ljava/util/List;ZZLx2/s;Lay0/k;Ll2/o;I)V

    .line 42
    .line 43
    .line 44
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_0
    iget-object v0, p0, Li91/r;->i:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v3, v0

    .line 50
    check-cast v3, Lon0/a0;

    .line 51
    .line 52
    iget-object v0, p0, Li91/r;->g:Llx0/e;

    .line 53
    .line 54
    move-object v4, v0

    .line 55
    check-cast v4, Lay0/a;

    .line 56
    .line 57
    iget-object v0, p0, Li91/r;->j:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v5, v0

    .line 60
    check-cast v5, Lay0/a;

    .line 61
    .line 62
    move-object v6, p1

    .line 63
    check-cast v6, Ll2/o;

    .line 64
    .line 65
    check-cast p2, Ljava/lang/Integer;

    .line 66
    .line 67
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 68
    .line 69
    .line 70
    iget p1, p0, Li91/r;->h:I

    .line 71
    .line 72
    or-int/lit8 p1, p1, 0x1

    .line 73
    .line 74
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    iget-boolean v1, p0, Li91/r;->e:Z

    .line 79
    .line 80
    iget-boolean v2, p0, Li91/r;->f:Z

    .line 81
    .line 82
    invoke-static/range {v1 .. v7}, Lx40/a;->D(ZZLon0/a0;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :pswitch_1
    iget-object v0, p0, Li91/r;->i:Ljava/lang/Object;

    .line 87
    .line 88
    move-object v1, v0

    .line 89
    check-cast v1, Ljava/lang/String;

    .line 90
    .line 91
    iget-object v0, p0, Li91/r;->g:Llx0/e;

    .line 92
    .line 93
    move-object v2, v0

    .line 94
    check-cast v2, Lay0/a;

    .line 95
    .line 96
    iget-object v0, p0, Li91/r;->j:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v3, v0

    .line 99
    check-cast v3, Lx2/s;

    .line 100
    .line 101
    move-object v6, p1

    .line 102
    check-cast v6, Ll2/o;

    .line 103
    .line 104
    check-cast p2, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    iget p1, p0, Li91/r;->h:I

    .line 110
    .line 111
    or-int/lit8 p1, p1, 0x1

    .line 112
    .line 113
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 114
    .line 115
    .line 116
    move-result v7

    .line 117
    iget-boolean v4, p0, Li91/r;->e:Z

    .line 118
    .line 119
    iget-boolean v5, p0, Li91/r;->f:Z

    .line 120
    .line 121
    invoke-static/range {v1 .. v7}, Li91/j0;->a0(Ljava/lang/String;Lay0/a;Lx2/s;ZZLl2/o;I)V

    .line 122
    .line 123
    .line 124
    goto :goto_0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
