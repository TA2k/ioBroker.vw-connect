.class public Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;
.super Lcom/google/android/gms/internal/measurement/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/gms/common/util/DynamiteApi;
.end annotation


# instance fields
.field public c:Lvp/g1;

.field public final d:Landroidx/collection/f;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.measurement.api.internal.IAppMeasurementDynamiteService"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/measurement/y;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 8
    .line 9
    new-instance v0, Landroidx/collection/f;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->d:Landroidx/collection/f;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "Attempting to perform action before initialize."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public beginAdUnitExposure(Ljava/lang/String;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->q:Lvp/w;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->e(Lvp/x;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p2, p3, p1}, Lvp/w;->b0(JLjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final c(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1, p2}, Lvp/d4;->I0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public clearConditionalUserProperty(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1, p2, p3}, Lvp/j2;->o0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public clearMeasurementEnabled(J)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Lvp/g1;

    .line 17
    .line 18
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 19
    .line 20
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 21
    .line 22
    .line 23
    new-instance p2, Lk0/g;

    .line 24
    .line 25
    const/16 v0, 0x11

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {p2, p0, v2, v1, v0}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, p2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public endAdUnitExposure(Ljava/lang/String;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->q:Lvp/w;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->e(Lvp/x;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p2, p3, p1}, Lvp/w;->c0(JLjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public generateEventId(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvp/d4;->W0()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1, v0, v1}, Lvp/d4;->J0(Lcom/google/android/gms/internal/measurement/m0;J)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public getAppInstanceId(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lvp/f1;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-direct {v1, p0, p1, v2}, Lvp/f1;-><init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Lcom/google/android/gms/internal/measurement/m0;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public getCachedAppInstanceId(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, v0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public getConditionalUserProperties(Ljava/lang/String;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ld6/z0;

    .line 12
    .line 13
    const/16 v2, 0x8

    .line 14
    .line 15
    const/4 v7, 0x0

    .line 16
    move-object v3, p0

    .line 17
    move-object v5, p1

    .line 18
    move-object v6, p2

    .line 19
    move-object v4, p3

    .line 20
    invoke-direct/range {v1 .. v7}, Ld6/z0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public getCurrentScreenClass(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/g1;->o:Lvp/u2;

    .line 16
    .line 17
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, v0, Lvp/u2;->g:Lvp/r2;

    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget-object v0, v0, Lvp/r2;->b:Ljava/lang/String;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public getCurrentScreenName(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/g1;->o:Lvp/u2;

    .line 16
    .line 17
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, v0, Lvp/u2;->g:Lvp/r2;

    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget-object v0, v0, Lvp/r2;->a:Ljava/lang/String;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public getGmpAppId(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvp/j2;->p0()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public getMaxUserProperties(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Lvp/g1;

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 25
    .line 26
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 27
    .line 28
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 29
    .line 30
    .line 31
    const/16 p1, 0x19

    .line 32
    .line 33
    invoke-virtual {p0, p2, p1}, Lvp/d4;->K0(Lcom/google/android/gms/internal/measurement/m0;I)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public getSessionId(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 16
    .line 17
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Llr/b;

    .line 21
    .line 22
    invoke-direct {v1, p0, p1}, Llr/b;-><init>(Lvp/j2;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public getTestFlag(Lcom/google/android/gms/internal/measurement/m0;I)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    if-eqz p2, :cond_4

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    if-eq p2, v0, :cond_3

    .line 8
    .line 9
    const/4 v0, 0x2

    .line 10
    if-eq p2, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x3

    .line 13
    if-eq p2, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    if-eq p2, v0, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 20
    .line 21
    iget-object p2, p2, Lvp/g1;->l:Lvp/d4;

    .line 22
    .line 23
    invoke-static {p2}, Lvp/g1;->g(Lap0/o;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 27
    .line 28
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 29
    .line 30
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 34
    .line 35
    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Lvp/g1;

    .line 41
    .line 42
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 43
    .line 44
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 45
    .line 46
    .line 47
    new-instance v5, Lvp/d2;

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    invoke-direct {v5, p0, v1, v2}, Lvp/d2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;I)V

    .line 51
    .line 52
    .line 53
    const-wide/16 v2, 0x3a98

    .line 54
    .line 55
    const-string v4, "boolean test flag value"

    .line 56
    .line 57
    invoke-virtual/range {v0 .. v5}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    check-cast p0, Ljava/lang/Boolean;

    .line 62
    .line 63
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    invoke-virtual {p2, p1, p0}, Lvp/d4;->M0(Lcom/google/android/gms/internal/measurement/m0;Z)V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :cond_1
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 72
    .line 73
    iget-object p2, p2, Lvp/g1;->l:Lvp/d4;

    .line 74
    .line 75
    invoke-static {p2}, Lvp/g1;->g(Lap0/o;)V

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 79
    .line 80
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 81
    .line 82
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 83
    .line 84
    .line 85
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 86
    .line 87
    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 88
    .line 89
    .line 90
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Lvp/g1;

    .line 93
    .line 94
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 95
    .line 96
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 97
    .line 98
    .line 99
    new-instance v5, Lvp/d2;

    .line 100
    .line 101
    const/4 v2, 0x2

    .line 102
    invoke-direct {v5, p0, v1, v2}, Lvp/d2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;I)V

    .line 103
    .line 104
    .line 105
    const-wide/16 v2, 0x3a98

    .line 106
    .line 107
    const-string v4, "int test flag value"

    .line 108
    .line 109
    invoke-virtual/range {v0 .. v5}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Ljava/lang/Integer;

    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    invoke-virtual {p2, p1, p0}, Lvp/d4;->K0(Lcom/google/android/gms/internal/measurement/m0;I)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :cond_2
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 124
    .line 125
    iget-object p2, p2, Lvp/g1;->l:Lvp/d4;

    .line 126
    .line 127
    invoke-static {p2}, Lvp/g1;->g(Lap0/o;)V

    .line 128
    .line 129
    .line 130
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 131
    .line 132
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 133
    .line 134
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 135
    .line 136
    .line 137
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 138
    .line 139
    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 140
    .line 141
    .line 142
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v0, Lvp/g1;

    .line 145
    .line 146
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 147
    .line 148
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 149
    .line 150
    .line 151
    new-instance v5, Lvp/f2;

    .line 152
    .line 153
    const/4 v2, 0x1

    .line 154
    invoke-direct {v5, p0, v1, v2}, Lvp/f2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;I)V

    .line 155
    .line 156
    .line 157
    const-wide/16 v2, 0x3a98

    .line 158
    .line 159
    const-string v4, "double test flag value"

    .line 160
    .line 161
    invoke-virtual/range {v0 .. v5}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    check-cast p0, Ljava/lang/Double;

    .line 166
    .line 167
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    .line 168
    .line 169
    .line 170
    move-result-wide v0

    .line 171
    new-instance p0, Landroid/os/Bundle;

    .line 172
    .line 173
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 174
    .line 175
    .line 176
    const-string v2, "r"

    .line 177
    .line 178
    invoke-virtual {p0, v2, v0, v1}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 179
    .line 180
    .line 181
    :try_start_0
    invoke-interface {p1, p0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 182
    .line 183
    .line 184
    return-void

    .line 185
    :catch_0
    move-exception v0

    .line 186
    move-object p0, v0

    .line 187
    iget-object p1, p2, Lap0/o;->e:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast p1, Lvp/g1;

    .line 190
    .line 191
    iget-object p1, p1, Lvp/g1;->i:Lvp/p0;

    .line 192
    .line 193
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 194
    .line 195
    .line 196
    iget-object p1, p1, Lvp/p0;->m:Lvp/n0;

    .line 197
    .line 198
    const-string p2, "Error returning double value to wrapper"

    .line 199
    .line 200
    invoke-virtual {p1, p0, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    return-void

    .line 204
    :cond_3
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 205
    .line 206
    iget-object p2, p2, Lvp/g1;->l:Lvp/d4;

    .line 207
    .line 208
    invoke-static {p2}, Lvp/g1;->g(Lap0/o;)V

    .line 209
    .line 210
    .line 211
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 212
    .line 213
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 214
    .line 215
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 216
    .line 217
    .line 218
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 219
    .line 220
    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 221
    .line 222
    .line 223
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v0, Lvp/g1;

    .line 226
    .line 227
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 228
    .line 229
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 230
    .line 231
    .line 232
    new-instance v5, Lvp/f2;

    .line 233
    .line 234
    const/4 v2, 0x0

    .line 235
    invoke-direct {v5, p0, v1, v2}, Lvp/f2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;I)V

    .line 236
    .line 237
    .line 238
    const-wide/16 v2, 0x3a98

    .line 239
    .line 240
    const-string v4, "long test flag value"

    .line 241
    .line 242
    invoke-virtual/range {v0 .. v5}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    check-cast p0, Ljava/lang/Long;

    .line 247
    .line 248
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 249
    .line 250
    .line 251
    move-result-wide v0

    .line 252
    invoke-virtual {p2, p1, v0, v1}, Lvp/d4;->J0(Lcom/google/android/gms/internal/measurement/m0;J)V

    .line 253
    .line 254
    .line 255
    return-void

    .line 256
    :cond_4
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 257
    .line 258
    iget-object p2, p2, Lvp/g1;->l:Lvp/d4;

    .line 259
    .line 260
    invoke-static {p2}, Lvp/g1;->g(Lap0/o;)V

    .line 261
    .line 262
    .line 263
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 264
    .line 265
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 266
    .line 267
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 268
    .line 269
    .line 270
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 271
    .line 272
    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 273
    .line 274
    .line 275
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v0, Lvp/g1;

    .line 278
    .line 279
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 280
    .line 281
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 282
    .line 283
    .line 284
    new-instance v5, Lvp/d2;

    .line 285
    .line 286
    const/4 v2, 0x1

    .line 287
    invoke-direct {v5, p0, v1, v2}, Lvp/d2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;I)V

    .line 288
    .line 289
    .line 290
    const-wide/16 v2, 0x3a98

    .line 291
    .line 292
    const-string v4, "String test flag value"

    .line 293
    .line 294
    invoke-virtual/range {v0 .. v5}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object p0

    .line 298
    check-cast p0, Ljava/lang/String;

    .line 299
    .line 300
    invoke-virtual {p2, p0, p1}, Lvp/d4;->I0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 301
    .line 302
    .line 303
    return-void
.end method

.method public getUserProperties(Ljava/lang/String;Ljava/lang/String;ZLcom/google/android/gms/internal/measurement/m0;)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lvp/a2;

    .line 12
    .line 13
    move-object v2, p0

    .line 14
    move-object v4, p1

    .line 15
    move-object v5, p2

    .line 16
    move v6, p3

    .line 17
    move-object v3, p4

    .line 18
    invoke-direct/range {v1 .. v6}, Lvp/a2;-><init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Lcom/google/android/gms/internal/measurement/m0;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public initForTests(Ljava/util/Map;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public initialize(Lyo/a;Lcom/google/android/gms/internal/measurement/u0;J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Landroid/content/Context;

    .line 10
    .line 11
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p3, p4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 15
    .line 16
    .line 17
    move-result-object p3

    .line 18
    invoke-static {p1, p2, p3}, Lvp/g1;->r(Landroid/content/Context;Lcom/google/android/gms/internal/measurement/u0;Ljava/lang/Long;)Lvp/g1;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 26
    .line 27
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 31
    .line 32
    const-string p1, "Attempting to initialize multiple times"

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public isDataCollectionEnabled(Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lvp/f1;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    invoke-direct {v1, p0, p1, v2}, Lvp/f1;-><init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Lcom/google/android/gms/internal/measurement/m0;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public logEvent(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;ZZJ)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    move-object v1, p1

    .line 12
    move-object v2, p2

    .line 13
    move-object v3, p3

    .line 14
    move v4, p4

    .line 15
    move v5, p5

    .line 16
    move-wide v6, p6

    .line 17
    invoke-virtual/range {v0 .. v7}, Lvp/j2;->f0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;ZZJ)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public logEventAndBundle(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Lcom/google/android/gms/internal/measurement/m0;J)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    if-eqz p3, :cond_0

    .line 8
    .line 9
    new-instance v0, Landroid/os/Bundle;

    .line 10
    .line 11
    invoke-direct {v0, p3}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    new-instance v0, Landroid/os/Bundle;

    .line 16
    .line 17
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 18
    .line 19
    .line 20
    :goto_0
    const-string v1, "_o"

    .line 21
    .line 22
    const-string v5, "app"

    .line 23
    .line 24
    invoke-virtual {v0, v1, v5}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    new-instance v2, Lvp/t;

    .line 28
    .line 29
    new-instance v4, Lvp/s;

    .line 30
    .line 31
    invoke-direct {v4, p3}, Lvp/s;-><init>(Landroid/os/Bundle;)V

    .line 32
    .line 33
    .line 34
    move-object v3, p2

    .line 35
    move-wide v6, p5

    .line 36
    invoke-direct/range {v2 .. v7}, Lvp/t;-><init>(Ljava/lang/String;Lvp/s;Ljava/lang/String;J)V

    .line 37
    .line 38
    .line 39
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 40
    .line 41
    iget-object v0, p2, Lvp/g1;->j:Lvp/e1;

    .line 42
    .line 43
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 44
    .line 45
    .line 46
    move-object p2, p0

    .line 47
    new-instance p0, Ld6/z0;

    .line 48
    .line 49
    move-object p5, p1

    .line 50
    const/4 p1, 0x5

    .line 51
    const/4 p6, 0x0

    .line 52
    move-object p3, p4

    .line 53
    move-object p4, v2

    .line 54
    invoke-direct/range {p0 .. p6}, Ld6/z0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, p0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public logHealthData(ILjava/lang/String;Lyo/a;Lyo/a;Lyo/a;)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    if-nez p3, :cond_0

    .line 6
    .line 7
    move-object v6, v0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    invoke-static {p3}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p3

    .line 13
    move-object v6, p3

    .line 14
    :goto_0
    if-nez p4, :cond_1

    .line 15
    .line 16
    move-object v7, v0

    .line 17
    goto :goto_1

    .line 18
    :cond_1
    invoke-static {p4}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p3

    .line 22
    move-object v7, p3

    .line 23
    :goto_1
    if-nez p5, :cond_2

    .line 24
    .line 25
    :goto_2
    move-object v8, v0

    .line 26
    goto :goto_3

    .line 27
    :cond_2
    invoke-static {p5}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    goto :goto_2

    .line 32
    :goto_3
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 33
    .line 34
    iget-object v1, p0, Lvp/g1;->i:Lvp/p0;

    .line 35
    .line 36
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 37
    .line 38
    .line 39
    const/4 v3, 0x1

    .line 40
    const/4 v4, 0x0

    .line 41
    move v2, p1

    .line 42
    move-object v5, p2

    .line 43
    invoke-virtual/range {v1 .. v8}, Lvp/p0;->j0(IZZLjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public onActivityCreated(Lyo/a;Landroid/os/Bundle;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivityCreatedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivityCreatedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p3, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p3, p3, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p3}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p3, p3, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    if-eqz p3, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/j2;->t0()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p3, p1, p2}, Lcom/google/firebase/messaging/k;->i(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public onActivityDestroyed(Lyo/a;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivityDestroyedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivityDestroyedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p2, p2, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p2}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p2, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/j2;->t0()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2, p1}, Lcom/google/firebase/messaging/k;->j(Lcom/google/android/gms/internal/measurement/w0;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public onActivityPaused(Lyo/a;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivityPausedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivityPausedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p2, p2, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p2}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p2, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/j2;->t0()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2, p1}, Lcom/google/firebase/messaging/k;->k(Lcom/google/android/gms/internal/measurement/w0;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public onActivityResumed(Lyo/a;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivityResumedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivityResumedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p2, p2, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p2}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p2, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/j2;->t0()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2, p1}, Lcom/google/firebase/messaging/k;->l(Lcom/google/android/gms/internal/measurement/w0;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public onActivitySaveInstanceState(Lyo/a;Lcom/google/android/gms/internal/measurement/m0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivitySaveInstanceStateByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Lcom/google/android/gms/internal/measurement/m0;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivitySaveInstanceStateByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Lcom/google/android/gms/internal/measurement/m0;J)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p3, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p3, p3, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p3}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p3, p3, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    new-instance p4, Landroid/os/Bundle;

    .line 14
    .line 15
    invoke-direct {p4}, Landroid/os/Bundle;-><init>()V

    .line 16
    .line 17
    .line 18
    if-eqz p3, :cond_0

    .line 19
    .line 20
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 21
    .line 22
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 23
    .line 24
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Lvp/j2;->t0()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p3, p1, p4}, Lcom/google/firebase/messaging/k;->m(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    :try_start_0
    invoke-interface {p2, p4}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :catch_0
    move-exception p1

    .line 38
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 39
    .line 40
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 41
    .line 42
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 46
    .line 47
    const-string p2, "Error returning bundle value to wrapper"

    .line 48
    .line 49
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public onActivityStarted(Lyo/a;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivityStartedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivityStartedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p1, p1, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p1}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p1, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/j2;->t0()V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public onActivityStopped(Lyo/a;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->onActivityStoppedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public onActivityStoppedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p1, p1, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p1}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p1, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lvp/j2;->t0()V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public performAction(Landroid/os/Bundle;Lcom/google/android/gms/internal/measurement/m0;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    invoke-interface {p2, p0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public registerOnMeasurementEventListener(Lcom/google/android/gms/internal/measurement/r0;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->d:Landroidx/collection/f;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    invoke-interface {p1}, Lcom/google/android/gms/internal/measurement/r0;->m()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lvp/u1;

    .line 20
    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    new-instance v1, Lvp/e4;

    .line 24
    .line 25
    invoke-direct {v1, p0, p1}, Lvp/e4;-><init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Lcom/google/android/gms/internal/measurement/r0;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p1}, Lcom/google/android/gms/internal/measurement/r0;->m()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-interface {v0, p1, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 44
    .line 45
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 46
    .line 47
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lvp/j2;->i:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 54
    .line 55
    invoke-virtual {p1, v1}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-nez p1, :cond_1

    .line 60
    .line 61
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Lvp/g1;

    .line 64
    .line 65
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 66
    .line 67
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 68
    .line 69
    .line 70
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 71
    .line 72
    const-string p1, "OnEventListener already registered"

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    :cond_1
    return-void

    .line 78
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 79
    throw p0
.end method

.method public resetAnalyticsData(J)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lvp/g1;

    .line 20
    .line 21
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 22
    .line 23
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lvp/b2;

    .line 27
    .line 28
    const/4 v2, 0x1

    .line 29
    invoke-direct {v1, p0, p1, p2, v2}, Lvp/b2;-><init>(Lvp/j2;JI)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public retrieveAndUploadBatches(Lcom/google/android/gms/internal/measurement/o0;)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    invoke-virtual {v1}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 4
    .line 5
    .line 6
    iget-object v0, v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 7
    .line 8
    iget-object v2, v0, Lvp/g1;->p:Lvp/j2;

    .line 9
    .line 10
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v2}, Lvp/b0;->b0()V

    .line 14
    .line 15
    .line 16
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Lvp/g1;

    .line 20
    .line 21
    iget-object v0, v3, Lvp/g1;->j:Lvp/e1;

    .line 22
    .line 23
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lvp/e1;->g0()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_c

    .line 31
    .line 32
    iget-object v0, v3, Lvp/g1;->j:Lvp/e1;

    .line 33
    .line 34
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 35
    .line 36
    .line 37
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    iget-object v0, v0, Lvp/e1;->h:Lvp/d1;

    .line 42
    .line 43
    if-ne v4, v0, :cond_0

    .line 44
    .line 45
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 46
    .line 47
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 48
    .line 49
    .line 50
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 51
    .line 52
    const-string v1, "Cannot retrieve and upload batches from analytics network thread"

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_0
    invoke-static {}, Lst/b;->i()Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-nez v0, :cond_b

    .line 63
    .line 64
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 65
    .line 66
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 67
    .line 68
    .line 69
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 70
    .line 71
    const-string v4, "[sgtm] Started client-side batch upload work."

    .line 72
    .line 73
    invoke-virtual {v0, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const/4 v0, 0x0

    .line 77
    const/4 v5, 0x0

    .line 78
    const/4 v6, 0x0

    .line 79
    :goto_0
    if-nez v0, :cond_a

    .line 80
    .line 81
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 82
    .line 83
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 84
    .line 85
    .line 86
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 87
    .line 88
    const-string v7, "[sgtm] Getting upload batches from service (FE)"

    .line 89
    .line 90
    invoke-virtual {v0, v7}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    new-instance v9, Ljava/util/concurrent/atomic/AtomicReference;

    .line 94
    .line 95
    invoke-direct {v9}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 96
    .line 97
    .line 98
    iget-object v8, v3, Lvp/g1;->j:Lvp/e1;

    .line 99
    .line 100
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 101
    .line 102
    .line 103
    new-instance v13, Lvp/f2;

    .line 104
    .line 105
    const/4 v0, 0x3

    .line 106
    const/4 v7, 0x0

    .line 107
    invoke-direct {v13, v2, v9, v0, v7}, Lvp/f2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;IZ)V

    .line 108
    .line 109
    .line 110
    const-wide/16 v10, 0x2710

    .line 111
    .line 112
    const-string v12, "[sgtm] Getting upload batches"

    .line 113
    .line 114
    invoke-virtual/range {v8 .. v13}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v9}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    check-cast v0, Lvp/t3;

    .line 122
    .line 123
    if-eqz v0, :cond_a

    .line 124
    .line 125
    iget-object v0, v0, Lvp/t3;->d:Ljava/util/List;

    .line 126
    .line 127
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 128
    .line 129
    .line 130
    move-result v7

    .line 131
    if-eqz v7, :cond_1

    .line 132
    .line 133
    goto/16 :goto_7

    .line 134
    .line 135
    :cond_1
    iget-object v7, v3, Lvp/g1;->i:Lvp/p0;

    .line 136
    .line 137
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 138
    .line 139
    .line 140
    iget-object v7, v7, Lvp/p0;->r:Lvp/n0;

    .line 141
    .line 142
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 143
    .line 144
    .line 145
    move-result v8

    .line 146
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v8

    .line 150
    const-string v9, "[sgtm] Retrieved upload batches. count"

    .line 151
    .line 152
    invoke-virtual {v7, v8, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 156
    .line 157
    .line 158
    move-result v7

    .line 159
    add-int/2addr v5, v7

    .line 160
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 161
    .line 162
    .line 163
    move-result-object v7

    .line 164
    :cond_2
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    if-eqz v0, :cond_9

    .line 169
    .line 170
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    move-object v8, v0

    .line 175
    check-cast v8, Lvp/r3;

    .line 176
    .line 177
    :try_start_0
    new-instance v0, Ljava/net/URI;

    .line 178
    .line 179
    iget-object v9, v8, Lvp/r3;->f:Ljava/lang/String;

    .line 180
    .line 181
    invoke-direct {v0, v9}, Ljava/net/URI;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0}, Ljava/net/URI;->toURL()Ljava/net/URL;

    .line 185
    .line 186
    .line 187
    move-result-object v13
    :try_end_0
    .catch Ljava/net/URISyntaxException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/net/MalformedURLException; {:try_start_0 .. :try_end_0} :catch_1

    .line 188
    new-instance v9, Ljava/util/concurrent/atomic/AtomicReference;

    .line 189
    .line 190
    invoke-direct {v9}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 191
    .line 192
    .line 193
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v0, Lvp/g1;

    .line 196
    .line 197
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 202
    .line 203
    .line 204
    iget-object v10, v0, Lvp/h0;->k:Ljava/lang/String;

    .line 205
    .line 206
    invoke-static {v10}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    iget-object v12, v0, Lvp/h0;->k:Ljava/lang/String;

    .line 210
    .line 211
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v0, Lvp/g1;

    .line 214
    .line 215
    iget-object v10, v0, Lvp/g1;->i:Lvp/p0;

    .line 216
    .line 217
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 218
    .line 219
    .line 220
    iget-object v10, v10, Lvp/p0;->r:Lvp/n0;

    .line 221
    .line 222
    iget-wide v14, v8, Lvp/r3;->d:J

    .line 223
    .line 224
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 225
    .line 226
    .line 227
    move-result-object v11

    .line 228
    iget-object v14, v8, Lvp/r3;->f:Ljava/lang/String;

    .line 229
    .line 230
    iget-object v15, v8, Lvp/r3;->e:[B

    .line 231
    .line 232
    array-length v15, v15

    .line 233
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 234
    .line 235
    .line 236
    move-result-object v15

    .line 237
    const-string v4, "[sgtm] Uploading data from app. row_id, url, uncompressed size"

    .line 238
    .line 239
    invoke-virtual {v10, v4, v11, v14, v15}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    iget-object v4, v8, Lvp/r3;->j:Ljava/lang/String;

    .line 243
    .line 244
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    if-nez v4, :cond_3

    .line 249
    .line 250
    iget-object v4, v0, Lvp/g1;->i:Lvp/p0;

    .line 251
    .line 252
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 253
    .line 254
    .line 255
    iget-object v4, v4, Lvp/p0;->r:Lvp/n0;

    .line 256
    .line 257
    iget-object v10, v8, Lvp/r3;->j:Ljava/lang/String;

    .line 258
    .line 259
    const-string v14, "[sgtm] Uploading data from app. row_id"

    .line 260
    .line 261
    invoke-virtual {v4, v11, v10, v14}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    :cond_3
    new-instance v15, Ljava/util/HashMap;

    .line 265
    .line 266
    invoke-direct {v15}, Ljava/util/HashMap;-><init>()V

    .line 267
    .line 268
    .line 269
    iget-object v4, v8, Lvp/r3;->g:Landroid/os/Bundle;

    .line 270
    .line 271
    invoke-virtual {v4}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 272
    .line 273
    .line 274
    move-result-object v10

    .line 275
    invoke-interface {v10}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 276
    .line 277
    .line 278
    move-result-object v10

    .line 279
    :cond_4
    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 280
    .line 281
    .line 282
    move-result v11

    .line 283
    if-eqz v11, :cond_5

    .line 284
    .line 285
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v11

    .line 289
    check-cast v11, Ljava/lang/String;

    .line 290
    .line 291
    invoke-virtual {v4, v11}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v14

    .line 295
    invoke-static {v14}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 296
    .line 297
    .line 298
    move-result v16

    .line 299
    if-nez v16, :cond_4

    .line 300
    .line 301
    invoke-virtual {v15, v11, v14}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    goto :goto_2

    .line 305
    :cond_5
    iget-object v11, v0, Lvp/g1;->r:Lvp/n2;

    .line 306
    .line 307
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 308
    .line 309
    .line 310
    iget-object v14, v8, Lvp/r3;->e:[B

    .line 311
    .line 312
    new-instance v4, Lrn/i;

    .line 313
    .line 314
    const/16 v10, 0x12

    .line 315
    .line 316
    invoke-direct {v4, v2, v9, v8, v10}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 317
    .line 318
    .line 319
    invoke-virtual {v11}, Lvp/n1;->c0()V

    .line 320
    .line 321
    .line 322
    invoke-static {v13}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    invoke-static {v14}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    iget-object v8, v11, Lap0/o;->e:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast v8, Lvp/g1;

    .line 331
    .line 332
    iget-object v8, v8, Lvp/g1;->j:Lvp/e1;

    .line 333
    .line 334
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 335
    .line 336
    .line 337
    new-instance v10, Lvp/r0;

    .line 338
    .line 339
    move-object/from16 v16, v4

    .line 340
    .line 341
    invoke-direct/range {v10 .. v16}, Lvp/r0;-><init>(Lvp/n2;Ljava/lang/String;Ljava/net/URL;[BLjava/util/HashMap;Lvp/l2;)V

    .line 342
    .line 343
    .line 344
    invoke-virtual {v8, v10}, Lvp/e1;->m0(Ljava/lang/Runnable;)V

    .line 345
    .line 346
    .line 347
    :try_start_1
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 348
    .line 349
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 350
    .line 351
    .line 352
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v0, Lvp/g1;

    .line 355
    .line 356
    iget-object v4, v0, Lvp/g1;->n:Lto/a;

    .line 357
    .line 358
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 359
    .line 360
    .line 361
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 362
    .line 363
    .line 364
    move-result-wide v10

    .line 365
    const-wide/32 v12, 0xea60

    .line 366
    .line 367
    .line 368
    add-long/2addr v10, v12

    .line 369
    monitor-enter v9
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0

    .line 370
    :goto_3
    :try_start_2
    invoke-virtual {v9}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v4

    .line 374
    if-nez v4, :cond_6

    .line 375
    .line 376
    const-wide/16 v14, 0x0

    .line 377
    .line 378
    cmp-long v4, v12, v14

    .line 379
    .line 380
    if-lez v4, :cond_6

    .line 381
    .line 382
    invoke-virtual {v9, v12, v13}, Ljava/lang/Object;->wait(J)V

    .line 383
    .line 384
    .line 385
    iget-object v4, v0, Lvp/g1;->n:Lto/a;

    .line 386
    .line 387
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 388
    .line 389
    .line 390
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 391
    .line 392
    .line 393
    move-result-wide v12

    .line 394
    sub-long v12, v10, v12

    .line 395
    .line 396
    goto :goto_3

    .line 397
    :catchall_0
    move-exception v0

    .line 398
    goto :goto_4

    .line 399
    :cond_6
    monitor-exit v9

    .line 400
    goto :goto_5

    .line 401
    :goto_4
    monitor-exit v9
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 402
    :try_start_3
    throw v0
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0

    .line 403
    :catch_0
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 404
    .line 405
    check-cast v0, Lvp/g1;

    .line 406
    .line 407
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 408
    .line 409
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 410
    .line 411
    .line 412
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 413
    .line 414
    const-string v4, "[sgtm] Interrupted waiting for uploading batch"

    .line 415
    .line 416
    invoke-virtual {v0, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    :goto_5
    invoke-virtual {v9}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    move-result-object v0

    .line 423
    if-nez v0, :cond_7

    .line 424
    .line 425
    sget-object v0, Lvp/p2;->e:Lvp/p2;

    .line 426
    .line 427
    goto :goto_6

    .line 428
    :cond_7
    invoke-virtual {v9}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    check-cast v0, Lvp/p2;

    .line 433
    .line 434
    goto :goto_6

    .line 435
    :catch_1
    move-exception v0

    .line 436
    iget-object v4, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 437
    .line 438
    check-cast v4, Lvp/g1;

    .line 439
    .line 440
    iget-object v4, v4, Lvp/g1;->i:Lvp/p0;

    .line 441
    .line 442
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 443
    .line 444
    .line 445
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 446
    .line 447
    iget-object v9, v8, Lvp/r3;->f:Ljava/lang/String;

    .line 448
    .line 449
    iget-wide v10, v8, Lvp/r3;->d:J

    .line 450
    .line 451
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 452
    .line 453
    .line 454
    move-result-object v8

    .line 455
    const-string v10, "[sgtm] Bad upload url for row_id"

    .line 456
    .line 457
    invoke-virtual {v4, v10, v9, v8, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 458
    .line 459
    .line 460
    sget-object v0, Lvp/p2;->g:Lvp/p2;

    .line 461
    .line 462
    :goto_6
    sget-object v4, Lvp/p2;->f:Lvp/p2;

    .line 463
    .line 464
    if-ne v0, v4, :cond_8

    .line 465
    .line 466
    add-int/lit8 v6, v6, 0x1

    .line 467
    .line 468
    goto/16 :goto_1

    .line 469
    .line 470
    :cond_8
    sget-object v4, Lvp/p2;->h:Lvp/p2;

    .line 471
    .line 472
    if-ne v0, v4, :cond_2

    .line 473
    .line 474
    const/4 v0, 0x1

    .line 475
    goto/16 :goto_0

    .line 476
    .line 477
    :cond_9
    const/4 v0, 0x0

    .line 478
    goto/16 :goto_0

    .line 479
    .line 480
    :cond_a
    :goto_7
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 481
    .line 482
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 483
    .line 484
    .line 485
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 486
    .line 487
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 488
    .line 489
    .line 490
    move-result-object v2

    .line 491
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 492
    .line 493
    .line 494
    move-result-object v3

    .line 495
    const-string v4, "[sgtm] Completed client-side batch upload work. total, success"

    .line 496
    .line 497
    invoke-virtual {v0, v2, v3, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    :try_start_4
    invoke-interface/range {p1 .. p1}, Lcom/google/android/gms/internal/measurement/o0;->k()V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_2

    .line 501
    .line 502
    .line 503
    goto :goto_8

    .line 504
    :catch_2
    move-exception v0

    .line 505
    iget-object v1, v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 506
    .line 507
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 508
    .line 509
    .line 510
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 511
    .line 512
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 513
    .line 514
    .line 515
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 516
    .line 517
    const-string v2, "Failed to call IDynamiteUploadBatchesCallback"

    .line 518
    .line 519
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 520
    .line 521
    .line 522
    :goto_8
    return-void

    .line 523
    :cond_b
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 524
    .line 525
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 526
    .line 527
    .line 528
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 529
    .line 530
    const-string v1, "Cannot retrieve and upload batches from main thread"

    .line 531
    .line 532
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    return-void

    .line 536
    :cond_c
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 537
    .line 538
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 539
    .line 540
    .line 541
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 542
    .line 543
    const-string v1, "Cannot retrieve and upload batches from analytics worker thread"

    .line 544
    .line 545
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 546
    .line 547
    .line 548
    return-void
.end method

.method public setConditionalUserProperty(Landroid/os/Bundle;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 7
    .line 8
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 14
    .line 15
    const-string p1, "Conditional user property must not be null"

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 22
    .line 23
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 24
    .line 25
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1, p2, p3}, Lvp/j2;->n0(Landroid/os/Bundle;J)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public setConsent(Landroid/os/Bundle;J)V
    .locals 0

    .line 1
    return-void
.end method

.method public setConsentThirdParty(Landroid/os/Bundle;J)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    const/16 v0, -0x14

    .line 12
    .line 13
    invoke-virtual {p0, p1, v0, p2, p3}, Lvp/j2;->u0(Landroid/os/Bundle;IJ)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setCurrentScreen(Lyo/a;Ljava/lang/String;Ljava/lang/String;J)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/app/Activity;

    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    move-object v0, p0

    .line 18
    move-object v2, p2

    .line 19
    move-object v3, p3

    .line 20
    move-wide v4, p4

    .line 21
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->setCurrentScreenByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Ljava/lang/String;Ljava/lang/String;J)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public setCurrentScreenByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Ljava/lang/String;Ljava/lang/String;J)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->o:Lvp/u2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p4, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p4, Lvp/g1;

    .line 14
    .line 15
    iget-object p5, p4, Lvp/g1;->g:Lvp/h;

    .line 16
    .line 17
    invoke-virtual {p5}, Lvp/h;->o0()Z

    .line 18
    .line 19
    .line 20
    move-result p5

    .line 21
    if-nez p5, :cond_0

    .line 22
    .line 23
    iget-object p0, p4, Lvp/g1;->i:Lvp/p0;

    .line 24
    .line 25
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 29
    .line 30
    const-string p1, "setCurrentScreen cannot be called while screen reporting is disabled."

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    iget-object p5, p0, Lvp/u2;->g:Lvp/r2;

    .line 37
    .line 38
    if-nez p5, :cond_1

    .line 39
    .line 40
    iget-object p0, p4, Lvp/g1;->i:Lvp/p0;

    .line 41
    .line 42
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 46
    .line 47
    const-string p1, "setCurrentScreen cannot be called while no activity active"

    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :cond_1
    iget-object v0, p0, Lvp/u2;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 54
    .line 55
    iget v1, p1, Lcom/google/android/gms/internal/measurement/w0;->d:I

    .line 56
    .line 57
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    if-nez v2, :cond_2

    .line 66
    .line 67
    iget-object p0, p4, Lvp/g1;->i:Lvp/p0;

    .line 68
    .line 69
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 70
    .line 71
    .line 72
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 73
    .line 74
    const-string p1, "setCurrentScreen must be called with an activity in the activity lifecycle"

    .line 75
    .line 76
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_2
    if-nez p3, :cond_3

    .line 81
    .line 82
    iget-object p3, p1, Lcom/google/android/gms/internal/measurement/w0;->e:Ljava/lang/String;

    .line 83
    .line 84
    invoke-virtual {p0, p3}, Lvp/u2;->h0(Ljava/lang/String;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p3

    .line 88
    :cond_3
    iget-object v2, p5, Lvp/r2;->b:Ljava/lang/String;

    .line 89
    .line 90
    iget-object p5, p5, Lvp/r2;->a:Ljava/lang/String;

    .line 91
    .line 92
    invoke-static {v2, p3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    invoke-static {p5, p2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p5

    .line 100
    if-eqz v2, :cond_5

    .line 101
    .line 102
    if-nez p5, :cond_4

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_4
    iget-object p0, p4, Lvp/g1;->i:Lvp/p0;

    .line 106
    .line 107
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 108
    .line 109
    .line 110
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 111
    .line 112
    const-string p1, "setCurrentScreen cannot be called with the same class and name"

    .line 113
    .line 114
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :cond_5
    :goto_0
    const/16 p5, 0x1f4

    .line 119
    .line 120
    if-eqz p2, :cond_7

    .line 121
    .line 122
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    if-lez v2, :cond_6

    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    iget-object v3, p4, Lvp/g1;->g:Lvp/h;

    .line 133
    .line 134
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    if-gt v2, p5, :cond_6

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_6
    iget-object p0, p4, Lvp/g1;->i:Lvp/p0;

    .line 141
    .line 142
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 143
    .line 144
    .line 145
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 146
    .line 147
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    const-string p2, "Invalid screen name length in setCurrentScreen. Length"

    .line 152
    .line 153
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    return-void

    .line 161
    :cond_7
    :goto_1
    if-eqz p3, :cond_9

    .line 162
    .line 163
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    if-lez v2, :cond_8

    .line 168
    .line 169
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 170
    .line 171
    .line 172
    move-result v2

    .line 173
    iget-object v3, p4, Lvp/g1;->g:Lvp/h;

    .line 174
    .line 175
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    if-gt v2, p5, :cond_8

    .line 179
    .line 180
    goto :goto_2

    .line 181
    :cond_8
    iget-object p0, p4, Lvp/g1;->i:Lvp/p0;

    .line 182
    .line 183
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 184
    .line 185
    .line 186
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 187
    .line 188
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 189
    .line 190
    .line 191
    move-result p1

    .line 192
    const-string p2, "Invalid class name length in setCurrentScreen. Length"

    .line 193
    .line 194
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :cond_9
    :goto_2
    iget-object p5, p4, Lvp/g1;->i:Lvp/p0;

    .line 203
    .line 204
    invoke-static {p5}, Lvp/g1;->k(Lvp/n1;)V

    .line 205
    .line 206
    .line 207
    iget-object p5, p5, Lvp/p0;->r:Lvp/n0;

    .line 208
    .line 209
    if-nez p2, :cond_a

    .line 210
    .line 211
    const-string v2, "null"

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_a
    move-object v2, p2

    .line 215
    :goto_3
    const-string v3, "Setting current screen to name, class"

    .line 216
    .line 217
    invoke-virtual {p5, v2, p3, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    new-instance p5, Lvp/r2;

    .line 221
    .line 222
    iget-object p4, p4, Lvp/g1;->l:Lvp/d4;

    .line 223
    .line 224
    invoke-static {p4}, Lvp/g1;->g(Lap0/o;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p4}, Lvp/d4;->W0()J

    .line 228
    .line 229
    .line 230
    move-result-wide v2

    .line 231
    invoke-direct {p5, v2, v3, p2, p3}, Lvp/r2;-><init>(JLjava/lang/String;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v0, v1, p5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/w0;->e:Ljava/lang/String;

    .line 238
    .line 239
    const/4 p2, 0x1

    .line 240
    invoke-virtual {p0, p1, p5, p2}, Lvp/u2;->j0(Ljava/lang/String;Lvp/r2;Z)V

    .line 241
    .line 242
    .line 243
    return-void
.end method

.method public setDataCollectionEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lvp/g1;

    .line 17
    .line 18
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 19
    .line 20
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 21
    .line 22
    .line 23
    new-instance v1, Lvp/z1;

    .line 24
    .line 25
    invoke-direct {v1, p0, p1}, Lvp/z1;-><init>(Lvp/j2;Z)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public setDefaultEventParameters(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    new-instance p1, Landroid/os/Bundle;

    .line 14
    .line 15
    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance v0, Landroid/os/Bundle;

    .line 20
    .line 21
    invoke-direct {v0, p1}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 22
    .line 23
    .line 24
    move-object p1, v0

    .line 25
    :goto_0
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Lvp/g1;

    .line 28
    .line 29
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 30
    .line 31
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 32
    .line 33
    .line 34
    new-instance v1, Lvp/e2;

    .line 35
    .line 36
    const/4 v2, 0x1

    .line 37
    invoke-direct {v1, p0, p1, v2}, Lvp/e2;-><init>(Lvp/j2;Landroid/os/Bundle;I)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public setEventInterceptor(Lcom/google/android/gms/internal/measurement/r0;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lc2/k;

    .line 5
    .line 6
    const/16 v1, 0x1b

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v0, p0, p1, v2, v1}, Lc2/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 13
    .line 14
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 15
    .line 16
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Lvp/e1;->g0()Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 26
    .line 27
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 28
    .line 29
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 36
    .line 37
    .line 38
    iget-object p1, p0, Lvp/j2;->h:Lc2/k;

    .line 39
    .line 40
    if-eq v0, p1, :cond_1

    .line 41
    .line 42
    if-nez p1, :cond_0

    .line 43
    .line 44
    const/4 p1, 0x1

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 p1, 0x0

    .line 47
    :goto_0
    const-string v1, "EventInterceptor already set."

    .line 48
    .line 49
    invoke-static {v1, p1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 50
    .line 51
    .line 52
    :cond_1
    iput-object v0, p0, Lvp/j2;->h:Lc2/k;

    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    iget-object p1, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 56
    .line 57
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 58
    .line 59
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    new-instance v1, Lk0/g;

    .line 63
    .line 64
    const/16 v2, 0x12

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    invoke-direct {v1, p0, v0, v3, v2}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 71
    .line 72
    .line 73
    return-void
.end method

.method public setInstanceIdProvider(Lcom/google/android/gms/internal/measurement/t0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public setMeasurementEnabled(ZJ)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 16
    .line 17
    .line 18
    iget-object p2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p2, Lvp/g1;

    .line 21
    .line 22
    iget-object p2, p2, Lvp/g1;->j:Lvp/e1;

    .line 23
    .line 24
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 25
    .line 26
    .line 27
    new-instance p3, Lk0/g;

    .line 28
    .line 29
    const/16 v0, 0x11

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {p3, p0, p1, v1, v0}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p2, p3}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public setMinimumSessionDuration(J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public setSessionTimeoutDuration(J)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 16
    .line 17
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lvp/b2;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-direct {v1, p0, p1, p2, v2}, Lvp/b2;-><init>(Lvp/j2;JI)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public setSgtmDebugInfo(Landroid/content/Intent;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lvp/g1;

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 22
    .line 23
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lvp/p0;->p:Lvp/n0;

    .line 27
    .line 28
    const-string p1, "Activity intent has no data. Preview Mode was not enabled."

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    const-string v0, "sgtm_debug_enable"

    .line 35
    .line 36
    invoke-virtual {p1, v0}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    if-eqz v0, :cond_3

    .line 41
    .line 42
    const-string v1, "1"

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    const-string v0, "sgtm_preview_key"

    .line 52
    .line 53
    invoke-virtual {p1, v0}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-nez v0, :cond_2

    .line 62
    .line 63
    iget-object v0, p0, Lvp/g1;->i:Lvp/p0;

    .line 64
    .line 65
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 66
    .line 67
    .line 68
    iget-object v0, v0, Lvp/p0;->p:Lvp/n0;

    .line 69
    .line 70
    const-string v1, "[sgtm] Preview Mode was enabled. Using the sgtmPreviewKey: "

    .line 71
    .line 72
    invoke-virtual {v0, p1, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lvp/g1;->g:Lvp/h;

    .line 76
    .line 77
    iput-object p1, p0, Lvp/h;->g:Ljava/lang/String;

    .line 78
    .line 79
    :cond_2
    return-void

    .line 80
    :cond_3
    :goto_0
    iget-object p1, p0, Lvp/g1;->i:Lvp/p0;

    .line 81
    .line 82
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p1, Lvp/p0;->p:Lvp/n0;

    .line 86
    .line 87
    const-string v0, "[sgtm] Preview Mode was not enabled."

    .line 88
    .line 89
    invoke-virtual {p1, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lvp/g1;->g:Lvp/h;

    .line 93
    .line 94
    const/4 p1, 0x0

    .line 95
    iput-object p1, p0, Lvp/h;->g:Ljava/lang/String;

    .line 96
    .line 97
    return-void
.end method

.method public setUserId(Ljava/lang/String;J)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 5
    .line 6
    iget-object v0, p0, Lvp/g1;->p:Lvp/j2;

    .line 7
    .line 8
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lvp/g1;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 24
    .line 25
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 29
    .line 30
    const-string p1, "User ID must be non-empty or null"

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 37
    .line 38
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 39
    .line 40
    .line 41
    new-instance v1, Lk0/g;

    .line 42
    .line 43
    const/16 v2, 0x14

    .line 44
    .line 45
    invoke-direct {v1, v2, v0, p1}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 49
    .line 50
    .line 51
    const-string v2, "_id"

    .line 52
    .line 53
    const/4 v4, 0x1

    .line 54
    const/4 v1, 0x0

    .line 55
    move-object v3, p1

    .line 56
    move-wide v5, p2

    .line 57
    invoke-virtual/range {v0 .. v6}, Lvp/j2;->k0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;ZJ)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public setUserProperty(Ljava/lang/String;Ljava/lang/String;Lyo/a;ZJ)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {p3}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p3

    .line 8
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 9
    .line 10
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 11
    .line 12
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual/range {p0 .. p6}, Lvp/j2;->k0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;ZJ)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public unregisterOnMeasurementEventListener(Lcom/google/android/gms/internal/measurement/r0;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->d:Landroidx/collection/f;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    invoke-interface {p1}, Lcom/google/android/gms/internal/measurement/r0;->m()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {v0, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lvp/u1;

    .line 20
    .line 21
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    new-instance v1, Lvp/e4;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lvp/e4;-><init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Lcom/google/android/gms/internal/measurement/r0;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 30
    .line 31
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 32
    .line 33
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lvp/j2;->i:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 40
    .line 41
    invoke-virtual {p1, v1}, Ljava/util/concurrent/CopyOnWriteArraySet;->remove(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-nez p1, :cond_1

    .line 46
    .line 47
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lvp/g1;

    .line 50
    .line 51
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 52
    .line 53
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 57
    .line 58
    const-string p1, "OnEventListener had not been registered"

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    return-void

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 66
    throw p0
.end method
