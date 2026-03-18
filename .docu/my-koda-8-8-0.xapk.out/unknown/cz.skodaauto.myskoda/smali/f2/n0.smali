.class public final synthetic Lf2/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:I

.field public final synthetic i:F

.field public final synthetic j:I

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;JJIFLay0/k;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lf2/n0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/n0;->k:Ljava/lang/Object;

    iput-object p2, p0, Lf2/n0;->e:Lx2/s;

    iput-wide p3, p0, Lf2/n0;->f:J

    iput-wide p5, p0, Lf2/n0;->g:J

    iput p7, p0, Lf2/n0;->h:I

    iput p8, p0, Lf2/n0;->i:F

    iput-object p9, p0, Lf2/n0;->l:Llx0/e;

    iput p10, p0, Lf2/n0;->j:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Le3/n0;JJFLt2/b;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lf2/n0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/n0;->e:Lx2/s;

    iput-object p2, p0, Lf2/n0;->k:Ljava/lang/Object;

    iput-wide p3, p0, Lf2/n0;->f:J

    iput-wide p5, p0, Lf2/n0;->g:J

    iput p7, p0, Lf2/n0;->i:F

    iput-object p8, p0, Lf2/n0;->l:Llx0/e;

    iput p9, p0, Lf2/n0;->h:I

    iput p10, p0, Lf2/n0;->j:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lf2/n0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lf2/n0;->k:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lay0/a;

    .line 10
    .line 11
    iget-object v0, p0, Lf2/n0;->l:Llx0/e;

    .line 12
    .line 13
    move-object v9, v0

    .line 14
    check-cast v9, Lay0/k;

    .line 15
    .line 16
    move-object v10, p1

    .line 17
    check-cast v10, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget p1, p0, Lf2/n0;->j:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v11

    .line 32
    iget-object v2, p0, Lf2/n0;->e:Lx2/s;

    .line 33
    .line 34
    iget-wide v3, p0, Lf2/n0;->f:J

    .line 35
    .line 36
    iget-wide v5, p0, Lf2/n0;->g:J

    .line 37
    .line 38
    iget v7, p0, Lf2/n0;->h:I

    .line 39
    .line 40
    iget v8, p0, Lf2/n0;->i:F

    .line 41
    .line 42
    invoke-static/range {v1 .. v11}, Lh2/n7;->c(Lay0/a;Lx2/s;JJIFLay0/k;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_0
    iget-object v0, p0, Lf2/n0;->k:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v2, v0

    .line 51
    check-cast v2, Le3/n0;

    .line 52
    .line 53
    iget-object v0, p0, Lf2/n0;->l:Llx0/e;

    .line 54
    .line 55
    move-object v8, v0

    .line 56
    check-cast v8, Lt2/b;

    .line 57
    .line 58
    move-object v9, p1

    .line 59
    check-cast v9, Ll2/o;

    .line 60
    .line 61
    check-cast p2, Ljava/lang/Integer;

    .line 62
    .line 63
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    iget p1, p0, Lf2/n0;->h:I

    .line 67
    .line 68
    or-int/lit8 p1, p1, 0x1

    .line 69
    .line 70
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 71
    .line 72
    .line 73
    move-result v10

    .line 74
    iget-object v1, p0, Lf2/n0;->e:Lx2/s;

    .line 75
    .line 76
    iget-wide v3, p0, Lf2/n0;->f:J

    .line 77
    .line 78
    iget-wide v5, p0, Lf2/n0;->g:J

    .line 79
    .line 80
    iget v7, p0, Lf2/n0;->i:F

    .line 81
    .line 82
    iget v11, p0, Lf2/n0;->j:I

    .line 83
    .line 84
    invoke-static/range {v1 .. v11}, Lkp/g7;->a(Lx2/s;Le3/n0;JJFLt2/b;Ll2/o;II)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
