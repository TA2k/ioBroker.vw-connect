.class public final Lv0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/w;


# instance fields
.field public final d:Lv0/e;

.field public final e:Landroidx/lifecycle/x;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/x;Lv0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv0/d;->e:Landroidx/lifecycle/x;

    .line 5
    .line 6
    iput-object p2, p0, Lv0/d;->d:Lv0/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onDestroy(Landroidx/lifecycle/x;)V
    .locals 0
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object p0, p0, Lv0/d;->d:Lv0/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lv0/e;->k(Landroidx/lifecycle/x;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onStart(Landroidx/lifecycle/x;)V
    .locals 0
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object p0, p0, Lv0/d;->d:Lv0/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lv0/e;->f(Landroidx/lifecycle/x;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onStop(Landroidx/lifecycle/x;)V
    .locals 0
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object p0, p0, Lv0/d;->d:Lv0/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lv0/e;->g(Landroidx/lifecycle/x;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
