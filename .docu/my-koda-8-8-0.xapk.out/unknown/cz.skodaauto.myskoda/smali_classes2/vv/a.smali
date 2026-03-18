.class public final Lvv/a;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Lay0/o;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lay0/o;III)V
    .locals 0

    .line 1
    iput p7, p0, Lvv/a;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lvv/a;->i:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lvv/a;->j:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lvv/a;->k:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lvv/a;->l:Lay0/o;

    .line 10
    .line 11
    iput p5, p0, Lvv/a;->g:I

    .line 12
    .line 13
    iput p6, p0, Lvv/a;->h:I

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lvv/a;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lvv/a;->i:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    check-cast v1, Lx4/v;

    .line 18
    .line 19
    iget-object p1, p0, Lvv/a;->j:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v2, p1

    .line 22
    check-cast v2, Lay0/a;

    .line 23
    .line 24
    iget-object p1, p0, Lvv/a;->k:Ljava/lang/Object;

    .line 25
    .line 26
    move-object v3, p1

    .line 27
    check-cast v3, Lx4/w;

    .line 28
    .line 29
    iget-object p1, p0, Lvv/a;->l:Lay0/o;

    .line 30
    .line 31
    move-object v4, p1

    .line 32
    check-cast v4, Lt2/b;

    .line 33
    .line 34
    iget p1, p0, Lvv/a;->g:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    iget v7, p0, Lvv/a;->h:I

    .line 43
    .line 44
    invoke-static/range {v1 .. v7}, Lx4/i;->a(Lx4/v;Lay0/a;Lx4/w;Lt2/b;Ll2/o;II)V

    .line 45
    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    move-object v4, p1

    .line 51
    check-cast v4, Ll2/o;

    .line 52
    .line 53
    check-cast p2, Ljava/lang/Number;

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 56
    .line 57
    .line 58
    iget-object p1, p0, Lvv/a;->i:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v0, p1

    .line 61
    check-cast v0, Lx2/s;

    .line 62
    .line 63
    iget-object p1, p0, Lvv/a;->j:Ljava/lang/Object;

    .line 64
    .line 65
    move-object v1, p1

    .line 66
    check-cast v1, Lvv/n0;

    .line 67
    .line 68
    iget-object p1, p0, Lvv/a;->k:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v2, p1

    .line 71
    check-cast v2, Lxf0/b2;

    .line 72
    .line 73
    iget p1, p0, Lvv/a;->g:I

    .line 74
    .line 75
    or-int/lit8 p1, p1, 0x1

    .line 76
    .line 77
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    iget v6, p0, Lvv/a;->h:I

    .line 82
    .line 83
    iget-object v3, p0, Lvv/a;->l:Lay0/o;

    .line 84
    .line 85
    invoke-static/range {v0 .. v6}, Llp/dc;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V

    .line 86
    .line 87
    .line 88
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
