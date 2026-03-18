.class public final Lf7/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Ly6/q;

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Lt2/b;

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public constructor <init>(Ly6/q;IILt2/b;II)V
    .locals 0

    .line 1
    iput-object p1, p0, Lf7/h;->f:Ly6/q;

    .line 2
    .line 3
    iput p2, p0, Lf7/h;->g:I

    .line 4
    .line 5
    iput p3, p0, Lf7/h;->h:I

    .line 6
    .line 7
    iput-object p4, p0, Lf7/h;->i:Lt2/b;

    .line 8
    .line 9
    iput p5, p0, Lf7/h;->j:I

    .line 10
    .line 11
    iput p6, p0, Lf7/h;->k:I

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lf7/h;->j:I

    .line 10
    .line 11
    or-int/lit8 v5, p1, 0x1

    .line 12
    .line 13
    iget v6, p0, Lf7/h;->k:I

    .line 14
    .line 15
    iget-object v0, p0, Lf7/h;->f:Ly6/q;

    .line 16
    .line 17
    iget v1, p0, Lf7/h;->g:I

    .line 18
    .line 19
    iget v2, p0, Lf7/h;->h:I

    .line 20
    .line 21
    iget-object v3, p0, Lf7/h;->i:Lt2/b;

    .line 22
    .line 23
    invoke-static/range {v0 .. v6}, Lkp/m7;->a(Ly6/q;IILt2/b;Ll2/o;II)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method
