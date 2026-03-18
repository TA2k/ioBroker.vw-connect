.class public final Lwv/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lvv/n0;

.field public final synthetic i:Lxf0/b2;

.field public final synthetic j:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/s;Lvv/n0;Lxf0/b2;Lt2/b;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lwv/d;->f:I

    .line 1
    iput-object p1, p0, Lwv/d;->g:Lx2/s;

    iput-object p2, p0, Lwv/d;->h:Lvv/n0;

    iput-object p3, p0, Lwv/d;->i:Lxf0/b2;

    iput-object p4, p0, Lwv/d;->j:Lt2/b;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lx2/s;Lvv/n0;Lxf0/b2;Lt2/b;I)V
    .locals 0

    const/4 p5, 0x1

    iput p5, p0, Lwv/d;->f:I

    .line 2
    iput-object p1, p0, Lwv/d;->g:Lx2/s;

    iput-object p2, p0, Lwv/d;->h:Lvv/n0;

    iput-object p3, p0, Lwv/d;->i:Lxf0/b2;

    iput-object p4, p0, Lwv/d;->j:Lt2/b;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lwv/d;->f:I

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
    const/16 p1, 0xc01

    .line 15
    .line 16
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 17
    .line 18
    .line 19
    move-result v6

    .line 20
    iget-object v1, p0, Lwv/d;->g:Lx2/s;

    .line 21
    .line 22
    iget-object v2, p0, Lwv/d;->h:Lvv/n0;

    .line 23
    .line 24
    iget-object v3, p0, Lwv/d;->i:Lxf0/b2;

    .line 25
    .line 26
    iget-object v4, p0, Lwv/d;->j:Lt2/b;

    .line 27
    .line 28
    invoke-static/range {v1 .. v6}, Lwv/f;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lt2/b;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    move-object v4, p1

    .line 35
    check-cast v4, Ll2/o;

    .line 36
    .line 37
    check-cast p2, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    and-int/lit8 p1, p1, 0xb

    .line 44
    .line 45
    const/4 p2, 0x2

    .line 46
    if-ne p1, p2, :cond_1

    .line 47
    .line 48
    move-object p1, v4

    .line 49
    check-cast p1, Ll2/t;

    .line 50
    .line 51
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    if-nez p2, :cond_0

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    :goto_0
    const/16 v5, 0x200

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    iget-object v0, p0, Lwv/d;->g:Lx2/s;

    .line 66
    .line 67
    iget-object v1, p0, Lwv/d;->h:Lvv/n0;

    .line 68
    .line 69
    iget-object v2, p0, Lwv/d;->i:Lxf0/b2;

    .line 70
    .line 71
    iget-object v3, p0, Lwv/d;->j:Lt2/b;

    .line 72
    .line 73
    invoke-static/range {v0 .. v6}, Llp/dc;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V

    .line 74
    .line 75
    .line 76
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
