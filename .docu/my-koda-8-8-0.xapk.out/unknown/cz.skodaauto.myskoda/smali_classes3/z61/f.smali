.class public final synthetic Lz61/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:J

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Landroidx/compose/foundation/layout/LayoutWeightElement;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZJLay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    const/4 p9, 0x0

    iput p9, p0, Lz61/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lz61/f;->i:Ljava/lang/Object;

    iput-boolean p2, p0, Lz61/f;->e:Z

    iput-object p3, p0, Lz61/f;->j:Ljava/lang/Object;

    iput-boolean p4, p0, Lz61/f;->h:Z

    iput-wide p5, p0, Lz61/f;->f:J

    iput-object p7, p0, Lz61/f;->g:Lay0/a;

    iput-object p8, p0, Lz61/f;->k:Llx0/e;

    return-void
.end method

.method public synthetic constructor <init>(ZLs1/e;JLay0/a;ZLay0/n;Lt2/b;I)V
    .locals 0

    .line 2
    const/4 p9, 0x1

    iput p9, p0, Lz61/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lz61/f;->e:Z

    iput-object p2, p0, Lz61/f;->i:Ljava/lang/Object;

    iput-wide p3, p0, Lz61/f;->f:J

    iput-object p5, p0, Lz61/f;->g:Lay0/a;

    iput-boolean p6, p0, Lz61/f;->h:Z

    iput-object p7, p0, Lz61/f;->j:Ljava/lang/Object;

    iput-object p8, p0, Lz61/f;->k:Llx0/e;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lz61/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lz61/f;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Ls1/e;

    .line 10
    .line 11
    iget-object v0, p0, Lz61/f;->j:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v7, v0

    .line 14
    check-cast v7, Lay0/n;

    .line 15
    .line 16
    iget-object v0, p0, Lz61/f;->k:Llx0/e;

    .line 17
    .line 18
    move-object v8, v0

    .line 19
    check-cast v8, Lt2/b;

    .line 20
    .line 21
    move-object v9, p1

    .line 22
    check-cast v9, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const p1, 0x180001

    .line 30
    .line 31
    .line 32
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 33
    .line 34
    .line 35
    move-result v10

    .line 36
    iget-boolean v1, p0, Lz61/f;->e:Z

    .line 37
    .line 38
    iget-wide v3, p0, Lz61/f;->f:J

    .line 39
    .line 40
    iget-object v5, p0, Lz61/f;->g:Lay0/a;

    .line 41
    .line 42
    iget-boolean v6, p0, Lz61/f;->h:Z

    .line 43
    .line 44
    invoke-static/range {v1 .. v10}, Lzb/b;->a(ZLs1/e;JLay0/a;ZLay0/n;Lt2/b;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    iget-object v0, p0, Lz61/f;->i:Ljava/lang/Object;

    .line 51
    .line 52
    move-object v1, v0

    .line 53
    check-cast v1, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 54
    .line 55
    iget-object v0, p0, Lz61/f;->j:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v3, v0

    .line 58
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 59
    .line 60
    iget-object v0, p0, Lz61/f;->k:Llx0/e;

    .line 61
    .line 62
    move-object v8, v0

    .line 63
    check-cast v8, Lay0/a;

    .line 64
    .line 65
    move-object v9, p1

    .line 66
    check-cast v9, Ll2/o;

    .line 67
    .line 68
    check-cast p2, Ljava/lang/Integer;

    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    const/4 p1, 0x1

    .line 74
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 75
    .line 76
    .line 77
    move-result v10

    .line 78
    iget-boolean v2, p0, Lz61/f;->e:Z

    .line 79
    .line 80
    iget-boolean v4, p0, Lz61/f;->h:Z

    .line 81
    .line 82
    iget-wide v5, p0, Lz61/f;->f:J

    .line 83
    .line 84
    iget-object v7, p0, Lz61/f;->g:Lay0/a;

    .line 85
    .line 86
    invoke-static/range {v1 .. v10}, Lz61/h;->b(Landroidx/compose/foundation/layout/LayoutWeightElement;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZJLay0/a;Lay0/a;Ll2/o;I)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
