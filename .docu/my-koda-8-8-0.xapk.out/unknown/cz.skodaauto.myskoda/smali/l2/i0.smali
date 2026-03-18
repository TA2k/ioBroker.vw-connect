.class public final Ll2/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# instance fields
.field public final d:Lay0/k;

.field public e:Ll2/j0;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/i0;->d:Lay0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/i0;->d:Lay0/k;

    .line 2
    .line 3
    sget-object v1, Ll2/l0;->a:Landroidx/compose/runtime/DisposableEffectScope;

    .line 4
    .line 5
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Ll2/j0;

    .line 10
    .line 11
    iput-object v0, p0, Ll2/i0;->e:Ll2/j0;

    .line 12
    .line 13
    return-void
.end method

.method public final e()V
    .locals 0

    .line 1
    return-void
.end method

.method public final h()V
    .locals 1

    .line 1
    iget-object v0, p0, Ll2/i0;->e:Ll2/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Ll2/j0;->dispose()V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Ll2/i0;->e:Ll2/j0;

    .line 10
    .line 11
    return-void
.end method
