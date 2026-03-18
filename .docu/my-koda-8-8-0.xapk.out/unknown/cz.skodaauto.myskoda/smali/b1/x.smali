.class public final Lb1/x;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Z

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lb1/t0;

.field public final synthetic i:Lb1/u0;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Lt2/b;

.field public final synthetic l:I


# direct methods
.method public constructor <init>(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;I)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lb1/x;->f:Z

    .line 2
    .line 3
    iput-object p2, p0, Lb1/x;->g:Lx2/s;

    .line 4
    .line 5
    iput-object p3, p0, Lb1/x;->h:Lb1/t0;

    .line 6
    .line 7
    iput-object p4, p0, Lb1/x;->i:Lb1/u0;

    .line 8
    .line 9
    iput-object p5, p0, Lb1/x;->j:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p6, p0, Lb1/x;->k:Lt2/b;

    .line 12
    .line 13
    iput p7, p0, Lb1/x;->l:I

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
    move-object v6, p1

    .line 2
    check-cast v6, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lb1/x;->l:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v7

    .line 17
    iget-boolean v0, p0, Lb1/x;->f:Z

    .line 18
    .line 19
    iget-object v1, p0, Lb1/x;->g:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Lb1/x;->h:Lb1/t0;

    .line 22
    .line 23
    iget-object v3, p0, Lb1/x;->i:Lb1/u0;

    .line 24
    .line 25
    iget-object v4, p0, Lb1/x;->j:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v5, p0, Lb1/x;->k:Lt2/b;

    .line 28
    .line 29
    invoke-static/range {v0 .. v7}, Landroidx/compose/animation/b;->c(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
