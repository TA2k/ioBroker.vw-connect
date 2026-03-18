.class public final Lj3/d0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lj3/e0;


# direct methods
.method public synthetic constructor <init>(Lj3/e0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lj3/d0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lj3/d0;->g:Lj3/e0;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lj3/d0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lg3/d;

    .line 7
    .line 8
    iget-object p0, p0, Lj3/d0;->g:Lj3/e0;

    .line 9
    .line 10
    iget-object v0, p0, Lj3/e0;->b:Lj3/c;

    .line 11
    .line 12
    iget v1, p0, Lj3/e0;->k:F

    .line 13
    .line 14
    iget p0, p0, Lj3/e0;->l:F

    .line 15
    .line 16
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {v2}, Lgw0/c;->o()J

    .line 21
    .line 22
    .line 23
    move-result-wide v3

    .line 24
    invoke-virtual {v2}, Lgw0/c;->h()Le3/r;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    invoke-interface {v5}, Le3/r;->o()V

    .line 29
    .line 30
    .line 31
    :try_start_0
    iget-object v5, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v5, Lbu/c;

    .line 34
    .line 35
    const-wide/16 v6, 0x0

    .line 36
    .line 37
    invoke-virtual {v5, v6, v7, v1, p0}, Lbu/c;->A(JFF)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, p1}, Lj3/c;->a(Lg3/d;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    invoke-static {v2, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 44
    .line 45
    .line 46
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    invoke-static {v2, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :pswitch_0
    check-cast p1, Lj3/c0;

    .line 55
    .line 56
    const/4 p1, 0x1

    .line 57
    iget-object p0, p0, Lj3/d0;->g:Lj3/e0;

    .line 58
    .line 59
    iput-boolean p1, p0, Lj3/e0;->d:Z

    .line 60
    .line 61
    iget-object p0, p0, Lj3/e0;->f:Lkotlin/jvm/internal/n;

    .line 62
    .line 63
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
