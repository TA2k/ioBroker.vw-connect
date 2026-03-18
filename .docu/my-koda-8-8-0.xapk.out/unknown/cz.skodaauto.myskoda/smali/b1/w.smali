.class public final Lb1/w;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Z

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Lb1/t0;

.field public final synthetic j:Lb1/u0;

.field public final synthetic k:Ljava/lang/String;

.field public final synthetic l:Lt2/b;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;III)V
    .locals 0

    .line 1
    iput p9, p0, Lb1/w;->f:I

    .line 2
    .line 3
    iput-boolean p1, p0, Lb1/w;->g:Z

    .line 4
    .line 5
    iput-object p2, p0, Lb1/w;->h:Lx2/s;

    .line 6
    .line 7
    iput-object p3, p0, Lb1/w;->i:Lb1/t0;

    .line 8
    .line 9
    iput-object p4, p0, Lb1/w;->j:Lb1/u0;

    .line 10
    .line 11
    iput-object p5, p0, Lb1/w;->k:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p6, p0, Lb1/w;->l:Lt2/b;

    .line 14
    .line 15
    iput p7, p0, Lb1/w;->m:I

    .line 16
    .line 17
    iput p8, p0, Lb1/w;->n:I

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lb1/w;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lb1/w;->m:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v8

    .line 22
    iget v9, p0, Lb1/w;->n:I

    .line 23
    .line 24
    iget-boolean v1, p0, Lb1/w;->g:Z

    .line 25
    .line 26
    iget-object v2, p0, Lb1/w;->h:Lx2/s;

    .line 27
    .line 28
    iget-object v3, p0, Lb1/w;->i:Lb1/t0;

    .line 29
    .line 30
    iget-object v4, p0, Lb1/w;->j:Lb1/u0;

    .line 31
    .line 32
    iget-object v5, p0, Lb1/w;->k:Ljava/lang/String;

    .line 33
    .line 34
    iget-object v6, p0, Lb1/w;->l:Lt2/b;

    .line 35
    .line 36
    invoke-static/range {v1 .. v9}, Landroidx/compose/animation/b;->e(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    move-object v6, p1

    .line 43
    check-cast v6, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Number;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 48
    .line 49
    .line 50
    iget p1, p0, Lb1/w;->m:I

    .line 51
    .line 52
    or-int/lit8 p1, p1, 0x1

    .line 53
    .line 54
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    iget v8, p0, Lb1/w;->n:I

    .line 59
    .line 60
    iget-boolean v0, p0, Lb1/w;->g:Z

    .line 61
    .line 62
    iget-object v1, p0, Lb1/w;->h:Lx2/s;

    .line 63
    .line 64
    iget-object v2, p0, Lb1/w;->i:Lb1/t0;

    .line 65
    .line 66
    iget-object v3, p0, Lb1/w;->j:Lb1/u0;

    .line 67
    .line 68
    iget-object v4, p0, Lb1/w;->k:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v5, p0, Lb1/w;->l:Lt2/b;

    .line 71
    .line 72
    invoke-static/range {v0 .. v8}, Landroidx/compose/animation/b;->d(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
