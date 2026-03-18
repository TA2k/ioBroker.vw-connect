.class public final synthetic Lvp/m2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Cloneable;


# direct methods
.method public synthetic constructor <init>(Lpv/g;ILvp/p0;Landroid/content/Intent;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/m2;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvp/m2;->f:Ljava/lang/Object;

    iput p2, p0, Lvp/m2;->e:I

    iput-object p3, p0, Lvp/m2;->g:Ljava/lang/Object;

    iput-object p4, p0, Lvp/m2;->h:Ljava/lang/Cloneable;

    return-void
.end method

.method public synthetic constructor <init>(Lvp/r0;ILjava/lang/Exception;[BLjava/util/Map;)V
    .locals 0

    const/4 p5, 0x0

    iput p5, p0, Lvp/m2;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvp/m2;->f:Ljava/lang/Object;

    iput p2, p0, Lvp/m2;->e:I

    iput-object p3, p0, Lvp/m2;->g:Ljava/lang/Object;

    iput-object p4, p0, Lvp/m2;->h:Ljava/lang/Cloneable;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    .line 1
    iget v0, p0, Lvp/m2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/m2;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lpv/g;

    .line 9
    .line 10
    iget-object v1, p0, Lvp/m2;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lvp/p0;

    .line 13
    .line 14
    iget-object v2, p0, Lvp/m2;->h:Ljava/lang/Cloneable;

    .line 15
    .line 16
    check-cast v2, Landroid/content/Intent;

    .line 17
    .line 18
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Landroid/app/Service;

    .line 21
    .line 22
    move-object v3, v0

    .line 23
    check-cast v3, Lvp/g3;

    .line 24
    .line 25
    iget p0, p0, Lvp/m2;->e:I

    .line 26
    .line 27
    invoke-interface {v3, p0}, Lvp/g3;->a(I)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_0

    .line 32
    .line 33
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 34
    .line 35
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string v4, "Local AppMeasurementService processed last upload request. StartId"

    .line 40
    .line 41
    invoke-virtual {v1, p0, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x0

    .line 45
    invoke-static {v0, p0, p0}, Lvp/g1;->r(Landroid/content/Context;Lcom/google/android/gms/internal/measurement/u0;Ljava/lang/Long;)Lvp/g1;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 50
    .line 51
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 55
    .line 56
    const-string v0, "Completed wakeful intent."

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-interface {v3, v2}, Lvp/g3;->b(Landroid/content/Intent;)V

    .line 62
    .line 63
    .line 64
    :cond_0
    return-void

    .line 65
    :pswitch_0
    iget-object v0, p0, Lvp/m2;->f:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, Lvp/r0;

    .line 68
    .line 69
    iget-object v1, p0, Lvp/m2;->g:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Ljava/lang/Exception;

    .line 72
    .line 73
    iget-object v2, p0, Lvp/m2;->h:Ljava/lang/Cloneable;

    .line 74
    .line 75
    check-cast v2, [B

    .line 76
    .line 77
    iget-object v0, v0, Lvp/r0;->i:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Lvp/l2;

    .line 80
    .line 81
    iget p0, p0, Lvp/m2;->e:I

    .line 82
    .line 83
    invoke-interface {v0, p0, v1, v2}, Lvp/l2;->h(ILjava/lang/Throwable;[B)V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
