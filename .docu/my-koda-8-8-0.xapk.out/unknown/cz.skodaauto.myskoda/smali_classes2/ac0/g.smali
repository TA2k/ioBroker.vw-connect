.class public final synthetic Lac0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lac0/g;->d:I

    iput-object p1, p0, Lac0/g;->e:Ljava/lang/String;

    iput-boolean p2, p0, Lac0/g;->f:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/String;I)V
    .locals 0

    .line 2
    iput p3, p0, Lac0/g;->d:I

    iput-boolean p1, p0, Lac0/g;->f:Z

    iput-object p2, p0, Lac0/g;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lac0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/e;

    .line 7
    .line 8
    iget-object v1, p0, Lac0/g;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-boolean p0, p0, Lac0/g;->f:Z

    .line 14
    .line 15
    xor-int/lit8 p0, p0, 0x1

    .line 16
    .line 17
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 18
    .line 19
    .line 20
    return-object v0

    .line 21
    :pswitch_0
    new-instance v0, Llj0/e;

    .line 22
    .line 23
    iget-object v1, p0, Lac0/g;->e:Ljava/lang/String;

    .line 24
    .line 25
    iget-boolean p0, p0, Lac0/g;->f:Z

    .line 26
    .line 27
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 28
    .line 29
    .line 30
    return-object v0

    .line 31
    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v1, "RPA isRunning = "

    .line 34
    .line 35
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Lac0/g;->f:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, " for vin = "

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lac0/g;->e:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_2
    new-instance v0, Llj0/e;

    .line 59
    .line 60
    iget-object v1, p0, Lac0/g;->e:Ljava/lang/String;

    .line 61
    .line 62
    iget-boolean p0, p0, Lac0/g;->f:Z

    .line 63
    .line 64
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 65
    .line 66
    .line 67
    return-object v0

    .line 68
    :pswitch_3
    iget-boolean v0, p0, Lac0/g;->f:Z

    .line 69
    .line 70
    if-eqz v0, :cond_0

    .line 71
    .line 72
    const-string v0, "Reconnected"

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    const-string v0, "Connected"

    .line 76
    .line 77
    :goto_0
    const-string v1, " to MQTT broker "

    .line 78
    .line 79
    const-string v2, "."

    .line 80
    .line 81
    iget-object p0, p0, Lac0/g;->e:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {v0, v1, p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
