.class public final Lu2/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu2/g;
.implements Lra/f;


# instance fields
.field public final synthetic d:Lu2/h;

.field public final e:Lra/e;

.field public final f:Landroidx/lifecycle/z;

.field public final g:Lra/d;


# direct methods
.method public constructor <init>(Lu2/h;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu2/j;->d:Lu2/h;

    .line 5
    .line 6
    new-instance v0, Lg11/c;

    .line 7
    .line 8
    new-instance v1, Lr1/b;

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    invoke-direct {v1, p0, v2}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v0, p0, v1}, Lg11/c;-><init>(Lra/f;Lr1/b;)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Lra/e;

    .line 18
    .line 19
    invoke-direct {v1, v0}, Lra/e;-><init>(Lg11/c;)V

    .line 20
    .line 21
    .line 22
    iput-object v1, p0, Lu2/j;->e:Lra/e;

    .line 23
    .line 24
    new-instance v0, Landroidx/lifecycle/z;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v0, p0, v2}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lu2/j;->f:Landroidx/lifecycle/z;

    .line 31
    .line 32
    iget-object v0, v1, Lra/e;->b:Lra/d;

    .line 33
    .line 34
    iput-object v0, p0, Lu2/j;->g:Lra/d;

    .line 35
    .line 36
    const-string v0, "androidx.savedstate.SavedStateRegistry"

    .line 37
    .line 38
    invoke-virtual {p1, v0}, Lu2/h;->f(Ljava/lang/String;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    instance-of v3, v2, Landroid/os/Bundle;

    .line 43
    .line 44
    if-eqz v3, :cond_0

    .line 45
    .line 46
    check-cast v2, Landroid/os/Bundle;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    const/4 v2, 0x0

    .line 50
    :goto_0
    invoke-virtual {v1, v2}, Lra/e;->b(Landroid/os/Bundle;)V

    .line 51
    .line 52
    .line 53
    new-instance v1, Lu2/a;

    .line 54
    .line 55
    const/4 v2, 0x1

    .line 56
    invoke-direct {v1, p0, v2}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1, v0, v1}, Lu2/h;->a(Ljava/lang/String;Lay0/a;)Lu2/f;

    .line 60
    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lay0/a;)Lu2/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/j;->d:Lu2/h;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lu2/h;->a(Ljava/lang/String;Lay0/a;)Lu2/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final d(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/j;->d:Lu2/h;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lu2/h;->d(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final e()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/j;->d:Lu2/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu2/h;->e()Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final f(Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/j;->d:Lu2/h;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lu2/h;->f(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getLifecycle()Landroidx/lifecycle/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/j;->f:Landroidx/lifecycle/z;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSavedStateRegistry()Lra/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/j;->g:Lra/d;

    .line 2
    .line 3
    return-object p0
.end method
