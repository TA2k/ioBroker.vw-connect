.class public final Lsu/c;
.super Landroid/animation/AnimatorListenerAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/animation/ValueAnimator$AnimatorUpdateListener;


# instance fields
.field public final a:Lsu/f;

.field public final b:Lsp/k;

.field public final c:Lcom/google/android/gms/maps/model/LatLng;

.field public final d:Lcom/google/android/gms/maps/model/LatLng;

.field public e:Z

.field public f:Ltu/b;

.field public final synthetic g:Lsu/i;


# direct methods
.method public constructor <init>(Lsu/i;Lsu/f;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lsu/c;->g:Lsu/i;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lsu/c;->a:Lsu/f;

    .line 7
    .line 8
    iget-object p1, p2, Lsu/f;->a:Lsp/k;

    .line 9
    .line 10
    iput-object p1, p0, Lsu/c;->b:Lsp/k;

    .line 11
    .line 12
    iput-object p3, p0, Lsu/c;->c:Lcom/google/android/gms/maps/model/LatLng;

    .line 13
    .line 14
    iput-object p4, p0, Lsu/c;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final onAnimationEnd(Landroid/animation/Animator;)V
    .locals 2

    .line 1
    iget-boolean p1, p0, Lsu/c;->e:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lsu/c;->g:Lsu/i;

    .line 6
    .line 7
    iget-object v0, p1, Lsu/i;->j:Lb81/c;

    .line 8
    .line 9
    iget-object v1, p0, Lsu/c;->b:Lsp/k;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lb81/c;->v(Lsp/k;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p1, Lsu/i;->m:Lb81/c;

    .line 15
    .line 16
    invoke-virtual {p1, v1}, Lb81/c;->v(Lsp/k;)V

    .line 17
    .line 18
    .line 19
    iget-object p1, p0, Lsu/c;->f:Ltu/b;

    .line 20
    .line 21
    invoke-virtual {p1, v1}, Ltu/b;->h(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    iget-object p1, p0, Lsu/c;->a:Lsu/f;

    .line 25
    .line 26
    iget-object p0, p0, Lsu/c;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 27
    .line 28
    iput-object p0, p1, Lsu/f;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 29
    .line 30
    return-void
.end method

.method public final onAnimationUpdate(Landroid/animation/ValueAnimator;)V
    .locals 12

    .line 1
    iget-object v0, p0, Lsu/c;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object v1, p0, Lsu/c;->c:Lcom/google/android/gms/maps/model/LatLng;

    .line 6
    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    iget-object p0, p0, Lsu/c;->b:Lsp/k;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p1}, Landroid/animation/ValueAnimator;->getAnimatedFraction()F

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    iget-wide v2, v0, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 19
    .line 20
    iget-wide v4, v1, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 21
    .line 22
    sub-double/2addr v2, v4

    .line 23
    float-to-double v6, p1

    .line 24
    mul-double/2addr v2, v6

    .line 25
    add-double/2addr v2, v4

    .line 26
    iget-wide v4, v0, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 27
    .line 28
    iget-wide v8, v1, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 29
    .line 30
    sub-double/2addr v4, v8

    .line 31
    invoke-static {v4, v5}, Ljava/lang/Math;->abs(D)D

    .line 32
    .line 33
    .line 34
    move-result-wide v8

    .line 35
    const-wide v10, 0x4066800000000000L    # 180.0

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    cmpl-double p1, v8, v10

    .line 41
    .line 42
    if-lez p1, :cond_1

    .line 43
    .line 44
    invoke-static {v4, v5}, Ljava/lang/Math;->signum(D)D

    .line 45
    .line 46
    .line 47
    move-result-wide v8

    .line 48
    const-wide v10, 0x4076800000000000L    # 360.0

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    mul-double/2addr v8, v10

    .line 54
    sub-double/2addr v4, v8

    .line 55
    :cond_1
    mul-double/2addr v4, v6

    .line 56
    iget-wide v0, v1, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 57
    .line 58
    add-double/2addr v4, v0

    .line 59
    new-instance p1, Lcom/google/android/gms/maps/model/LatLng;

    .line 60
    .line 61
    invoke-direct {p1, v2, v3, v4, v5}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1}, Lsp/k;->e(Lcom/google/android/gms/maps/model/LatLng;)V

    .line 65
    .line 66
    .line 67
    :cond_2
    :goto_0
    return-void
.end method
