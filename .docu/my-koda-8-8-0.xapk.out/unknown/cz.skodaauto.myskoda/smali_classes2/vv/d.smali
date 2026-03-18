.class public final Lvv/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Lt3/e1;

.field public final synthetic g:Lt3/e1;

.field public final synthetic h:I


# direct methods
.method public constructor <init>(Lt3/e1;Lt3/e1;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/d;->f:Lt3/e1;

    .line 2
    .line 3
    iput-object p2, p0, Lvv/d;->g:Lt3/e1;

    .line 4
    .line 5
    iput p3, p0, Lvv/d;->h:I

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    const-string v0, "$this$layout"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lvv/d;->f:Lt3/e1;

    .line 9
    .line 10
    const-wide/16 v1, 0x0

    .line 11
    .line 12
    invoke-static {p1, v0, v1, v2}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 13
    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    const/4 v1, 0x0

    .line 17
    iget-object v2, p0, Lvv/d;->g:Lt3/e1;

    .line 18
    .line 19
    iget p0, p0, Lvv/d;->h:I

    .line 20
    .line 21
    invoke-virtual {p1, v2, p0, v0, v1}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method
