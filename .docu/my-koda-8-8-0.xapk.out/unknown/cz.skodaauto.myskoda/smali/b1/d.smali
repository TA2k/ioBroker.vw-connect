.class public final Lb1/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Lt2/b;

.field public final synthetic j:I

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Ljava/lang/Object;

.field public final synthetic n:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc1/w1;Lay0/k;Lx2/s;Lb1/t0;Lb1/u0;Lay0/n;Lt2/b;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lb1/d;->f:I

    .line 1
    iput-object p1, p0, Lb1/d;->k:Ljava/lang/Object;

    iput-object p2, p0, Lb1/d;->g:Lay0/k;

    iput-object p3, p0, Lb1/d;->h:Lx2/s;

    iput-object p4, p0, Lb1/d;->l:Ljava/lang/Object;

    iput-object p5, p0, Lb1/d;->m:Ljava/lang/Object;

    iput-object p6, p0, Lb1/d;->n:Ljava/lang/Object;

    iput-object p7, p0, Lb1/d;->i:Lt2/b;

    iput p8, p0, Lb1/d;->j:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lh2/o4;Lx2/s;Lay0/k;Lx2/e;Ljava/lang/String;Lay0/k;Lt2/b;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb1/d;->f:I

    .line 2
    iput-object p1, p0, Lb1/d;->k:Ljava/lang/Object;

    iput-object p2, p0, Lb1/d;->h:Lx2/s;

    iput-object p3, p0, Lb1/d;->g:Lay0/k;

    iput-object p4, p0, Lb1/d;->m:Ljava/lang/Object;

    iput-object p5, p0, Lb1/d;->n:Ljava/lang/Object;

    iput-object p6, p0, Lb1/d;->l:Ljava/lang/Object;

    iput-object p7, p0, Lb1/d;->i:Lt2/b;

    iput p8, p0, Lb1/d;->j:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lb1/d;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v8, p1

    .line 7
    check-cast v8, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lb1/d;->k:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    check-cast v1, Lc1/w1;

    .line 18
    .line 19
    iget-object p1, p0, Lb1/d;->l:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v4, p1

    .line 22
    check-cast v4, Lb1/t0;

    .line 23
    .line 24
    iget-object p1, p0, Lb1/d;->m:Ljava/lang/Object;

    .line 25
    .line 26
    move-object v5, p1

    .line 27
    check-cast v5, Lb1/u0;

    .line 28
    .line 29
    iget-object p1, p0, Lb1/d;->n:Ljava/lang/Object;

    .line 30
    .line 31
    move-object v6, p1

    .line 32
    check-cast v6, Lay0/n;

    .line 33
    .line 34
    iget p1, p0, Lb1/d;->j:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v9

    .line 42
    iget-object v2, p0, Lb1/d;->g:Lay0/k;

    .line 43
    .line 44
    iget-object v3, p0, Lb1/d;->h:Lx2/s;

    .line 45
    .line 46
    iget-object v7, p0, Lb1/d;->i:Lt2/b;

    .line 47
    .line 48
    invoke-static/range {v1 .. v9}, Landroidx/compose/animation/b;->a(Lc1/w1;Lay0/k;Lx2/s;Lb1/t0;Lb1/u0;Lay0/n;Lt2/b;Ll2/o;I)V

    .line 49
    .line 50
    .line 51
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_0
    move-object v7, p1

    .line 55
    check-cast v7, Ll2/o;

    .line 56
    .line 57
    check-cast p2, Ljava/lang/Number;

    .line 58
    .line 59
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Lb1/d;->k:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v0, p1

    .line 65
    check-cast v0, Lh2/o4;

    .line 66
    .line 67
    iget-object p1, p0, Lb1/d;->m:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v3, p1

    .line 70
    check-cast v3, Lx2/e;

    .line 71
    .line 72
    iget-object p1, p0, Lb1/d;->n:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v4, p1

    .line 75
    check-cast v4, Ljava/lang/String;

    .line 76
    .line 77
    iget-object p1, p0, Lb1/d;->l:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v5, p1

    .line 80
    check-cast v5, Lay0/k;

    .line 81
    .line 82
    iget p1, p0, Lb1/d;->j:I

    .line 83
    .line 84
    or-int/lit8 p1, p1, 0x1

    .line 85
    .line 86
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 87
    .line 88
    .line 89
    move-result v8

    .line 90
    iget-object v1, p0, Lb1/d;->h:Lx2/s;

    .line 91
    .line 92
    iget-object v2, p0, Lb1/d;->g:Lay0/k;

    .line 93
    .line 94
    iget-object v6, p0, Lb1/d;->i:Lt2/b;

    .line 95
    .line 96
    invoke-static/range {v0 .. v8}, Landroidx/compose/animation/a;->b(Lh2/o4;Lx2/s;Lay0/k;Lx2/e;Ljava/lang/String;Lay0/k;Lt2/b;Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
