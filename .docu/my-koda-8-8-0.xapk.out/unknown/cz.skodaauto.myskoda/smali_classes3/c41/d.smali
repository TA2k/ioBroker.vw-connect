.class public final synthetic Lc41/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lh2/v3;ILx2/s;JI)V
    .locals 0

    .line 1
    const/4 p6, 0x2

    iput p6, p0, Lc41/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/d;->g:Ljava/lang/Object;

    iput p2, p0, Lc41/d;->f:I

    iput-object p3, p0, Lc41/d;->h:Ljava/lang/Object;

    iput-wide p4, p0, Lc41/d;->e:J

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;JLay0/k;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lc41/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/d;->g:Ljava/lang/Object;

    iput-wide p2, p0, Lc41/d;->e:J

    iput-object p4, p0, Lc41/d;->h:Ljava/lang/Object;

    iput p5, p0, Lc41/d;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Li3/c;JI)V
    .locals 1

    .line 3
    const/4 v0, 0x1

    iput v0, p0, Lc41/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/d;->g:Ljava/lang/Object;

    iput-object p2, p0, Lc41/d;->h:Ljava/lang/Object;

    iput-wide p3, p0, Lc41/d;->e:J

    iput p5, p0, Lc41/d;->f:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lc41/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc41/d;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lh2/v3;

    .line 10
    .line 11
    iget-object v0, p0, Lc41/d;->h:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v7, v0

    .line 14
    check-cast v7, Lx2/s;

    .line 15
    .line 16
    move-object v6, p1

    .line 17
    check-cast v6, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/16 p1, 0xc31

    .line 25
    .line 26
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    iget v2, p0, Lc41/d;->f:I

    .line 31
    .line 32
    iget-wide v4, p0, Lc41/d;->e:J

    .line 33
    .line 34
    invoke-virtual/range {v1 .. v7}, Lh2/v3;->c(IIJLl2/o;Lx2/s;)V

    .line 35
    .line 36
    .line 37
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    iget-object v0, p0, Lc41/d;->g:Ljava/lang/Object;

    .line 41
    .line 42
    move-object v1, v0

    .line 43
    check-cast v1, Lx2/s;

    .line 44
    .line 45
    iget-object v0, p0, Lc41/d;->h:Ljava/lang/Object;

    .line 46
    .line 47
    move-object v2, v0

    .line 48
    check-cast v2, Li3/c;

    .line 49
    .line 50
    move-object v5, p1

    .line 51
    check-cast v5, Ll2/o;

    .line 52
    .line 53
    check-cast p2, Ljava/lang/Integer;

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    iget p1, p0, Lc41/d;->f:I

    .line 59
    .line 60
    or-int/lit8 p1, p1, 0x1

    .line 61
    .line 62
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 63
    .line 64
    .line 65
    move-result v6

    .line 66
    iget-wide v3, p0, Lc41/d;->e:J

    .line 67
    .line 68
    invoke-static/range {v1 .. v6}, Lkp/i0;->b(Lx2/s;Li3/c;JLl2/o;I)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_1
    iget-object v0, p0, Lc41/d;->g:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v1, v0

    .line 75
    check-cast v1, Ljava/lang/String;

    .line 76
    .line 77
    iget-object v0, p0, Lc41/d;->h:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v4, v0

    .line 80
    check-cast v4, Lay0/k;

    .line 81
    .line 82
    move-object v5, p1

    .line 83
    check-cast v5, Ll2/o;

    .line 84
    .line 85
    check-cast p2, Ljava/lang/Integer;

    .line 86
    .line 87
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    iget p1, p0, Lc41/d;->f:I

    .line 91
    .line 92
    or-int/lit8 p1, p1, 0x1

    .line 93
    .line 94
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 95
    .line 96
    .line 97
    move-result v6

    .line 98
    iget-wide v2, p0, Lc41/d;->e:J

    .line 99
    .line 100
    invoke-static/range {v1 .. v6}, Ljp/wc;->b(Ljava/lang/String;JLay0/k;Ll2/o;I)V

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
