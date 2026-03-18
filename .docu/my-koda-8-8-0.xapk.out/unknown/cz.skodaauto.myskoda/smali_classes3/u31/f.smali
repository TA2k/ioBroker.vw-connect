.class public final synthetic Lu31/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu31/h;


# direct methods
.method public synthetic constructor <init>(Lu31/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lu31/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu31/f;->e:Lu31/h;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lu31/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ln7/b;

    .line 7
    .line 8
    const-string v0, "$this$LifecycleStartEffect"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sget-object v0, Lu31/c;->a:Lu31/c;

    .line 14
    .line 15
    iget-object p0, p0, Lu31/f;->e:Lu31/h;

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lu31/h;->b(Lu31/e;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Ly21/e;

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    invoke-direct {v0, p1, p0, v1}, Ly21/e;-><init>(Ln7/b;Lq41/b;I)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    move-object v2, p1

    .line 28
    check-cast v2, Li31/b;

    .line 29
    .line 30
    const-string p1, "$this$updateCurrentAppointmentUseCase"

    .line 31
    .line 32
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lu31/f;->e:Lu31/h;

    .line 36
    .line 37
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Lu31/i;

    .line 42
    .line 43
    iget-boolean p0, p0, Lu31/i;->a:Z

    .line 44
    .line 45
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 46
    .line 47
    .line 48
    move-result-object v8

    .line 49
    const/4 v9, 0x0

    .line 50
    const/16 v10, 0x5f

    .line 51
    .line 52
    const/4 v3, 0x0

    .line 53
    const/4 v4, 0x0

    .line 54
    const/4 v5, 0x0

    .line 55
    const/4 v6, 0x0

    .line 56
    const/4 v7, 0x0

    .line 57
    invoke-static/range {v2 .. v10}, Li31/b;->a(Li31/b;Ljava/lang/String;Li31/b0;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;I)Li31/b;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
