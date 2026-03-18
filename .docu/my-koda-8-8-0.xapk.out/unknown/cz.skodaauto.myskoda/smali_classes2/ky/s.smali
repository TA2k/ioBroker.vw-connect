.class public final synthetic Lky/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lss0/d0;


# direct methods
.method public synthetic constructor <init>(Lss0/d0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lky/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lky/s;->e:Lss0/d0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lky/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 7
    .line 8
    check-cast p0, Lss0/g;

    .line 9
    .line 10
    iget-object p0, p0, Lss0/g;->d:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p0}, Lss0/g;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, "No vehicle provided with CommissionId "

    .line 17
    .line 18
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 24
    .line 25
    check-cast p0, Lss0/g;

    .line 26
    .line 27
    iget-object p0, p0, Lss0/g;->d:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {p0}, Lss0/g;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "Ordered vehicle doesn\'t have vin "

    .line 34
    .line 35
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 41
    .line 42
    check-cast p0, Lss0/j0;

    .line 43
    .line 44
    iget-object p0, p0, Lss0/j0;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {p0}, Lss0/j0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    const-string v0, "No vehicle provided with VIN "

    .line 51
    .line 52
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 58
    .line 59
    check-cast p0, Lss0/g;

    .line 60
    .line 61
    iget-object p0, p0, Lss0/g;->d:Ljava/lang/String;

    .line 62
    .line 63
    const-string v0, "(MDK) Vehicle is in commission. ID="

    .line 64
    .line 65
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :pswitch_3
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 71
    .line 72
    check-cast p0, Lss0/g;

    .line 73
    .line 74
    iget-object p0, p0, Lss0/g;->d:Ljava/lang/String;

    .line 75
    .line 76
    const-string v0, "(MDK) Vehicle is in commission. ID="

    .line 77
    .line 78
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_4
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 84
    .line 85
    check-cast p0, Lss0/g;

    .line 86
    .line 87
    iget-object p0, p0, Lss0/g;->d:Ljava/lang/String;

    .line 88
    .line 89
    const-string v0, "(MDK) Vehicle is in commission. ID="

    .line 90
    .line 91
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    :pswitch_5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 99
    .line 100
    .line 101
    iget-object p0, p0, Lky/s;->e:Lss0/d0;

    .line 102
    .line 103
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string p0, " is not selected"

    .line 107
    .line 108
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
