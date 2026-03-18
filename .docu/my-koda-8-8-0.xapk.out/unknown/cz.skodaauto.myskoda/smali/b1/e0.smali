.class public final Lb1/e0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;III)V
    .locals 0

    .line 1
    iput p8, p0, Lb1/e0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/e0;->j:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lb1/e0;->g:Lx2/s;

    .line 6
    .line 7
    iput-object p3, p0, Lb1/e0;->k:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lb1/e0;->l:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lb1/e0;->m:Llx0/e;

    .line 12
    .line 13
    iput p6, p0, Lb1/e0;->h:I

    .line 14
    .line 15
    iput p7, p0, Lb1/e0;->i:I

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lb1/e0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lb1/e0;->j:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    check-cast v1, Lay0/k;

    .line 18
    .line 19
    iget-object p1, p0, Lb1/e0;->k:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v3, p1

    .line 22
    check-cast v3, Lay0/k;

    .line 23
    .line 24
    iget-object p1, p0, Lb1/e0;->l:Ljava/lang/Object;

    .line 25
    .line 26
    move-object v4, p1

    .line 27
    check-cast v4, Lay0/k;

    .line 28
    .line 29
    iget-object p1, p0, Lb1/e0;->m:Llx0/e;

    .line 30
    .line 31
    move-object v5, p1

    .line 32
    check-cast v5, Lay0/k;

    .line 33
    .line 34
    iget p1, p0, Lb1/e0;->h:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    iget v8, p0, Lb1/e0;->i:I

    .line 43
    .line 44
    iget-object v2, p0, Lb1/e0;->g:Lx2/s;

    .line 45
    .line 46
    invoke-static/range {v1 .. v8}, Landroidx/compose/ui/viewinterop/a;->b(Lay0/k;Lx2/s;Lay0/k;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 47
    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_0
    move-object v5, p1

    .line 53
    check-cast v5, Ll2/o;

    .line 54
    .line 55
    check-cast p2, Ljava/lang/Number;

    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lb1/e0;->k:Ljava/lang/Object;

    .line 61
    .line 62
    move-object v2, p1

    .line 63
    check-cast v2, Lc1/a0;

    .line 64
    .line 65
    iget-object p1, p0, Lb1/e0;->l:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v3, p1

    .line 68
    check-cast v3, Ljava/lang/String;

    .line 69
    .line 70
    iget-object p1, p0, Lb1/e0;->m:Llx0/e;

    .line 71
    .line 72
    move-object v4, p1

    .line 73
    check-cast v4, Lt2/b;

    .line 74
    .line 75
    iget p1, p0, Lb1/e0;->h:I

    .line 76
    .line 77
    or-int/lit8 p1, p1, 0x1

    .line 78
    .line 79
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    iget v7, p0, Lb1/e0;->i:I

    .line 84
    .line 85
    iget-object v0, p0, Lb1/e0;->j:Ljava/lang/Object;

    .line 86
    .line 87
    iget-object v1, p0, Lb1/e0;->g:Lx2/s;

    .line 88
    .line 89
    invoke-static/range {v0 .. v7}, Ljp/w1;->b(Ljava/lang/Object;Lx2/s;Lc1/a0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 90
    .line 91
    .line 92
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
