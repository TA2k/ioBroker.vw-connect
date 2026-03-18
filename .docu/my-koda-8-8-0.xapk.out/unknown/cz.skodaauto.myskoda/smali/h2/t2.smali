.class public final synthetic Lh2/t2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm1/t;


# direct methods
.method public synthetic constructor <init>(Lm1/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/t2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/t2;->e:Lm1/t;

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
    iget v0, p0, Lh2/t2;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lh2/t2;->e:Lm1/t;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 9
    .line 10
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 11
    .line 12
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    iget-object p0, p0, Lm1/l;->k:Ljava/lang/Object;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 29
    .line 30
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 31
    .line 32
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_2
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    iget p0, p0, Lm1/l;->n:I

    .line 46
    .line 47
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :pswitch_3
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 53
    .line 54
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 55
    .line 56
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-nez p0, :cond_0

    .line 61
    .line 62
    const/4 p0, 0x1

    .line 63
    goto :goto_0

    .line 64
    :cond_0
    const/4 p0, 0x0

    .line 65
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :pswitch_4
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 71
    .line 72
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 73
    .line 74
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    if-nez p0, :cond_1

    .line 79
    .line 80
    const/4 p0, 0x1

    .line 81
    goto :goto_1

    .line 82
    :cond_1
    const/4 p0, 0x0

    .line 83
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    iget-object p0, p0, Lm1/t;->e:Lm1/o;

    .line 89
    .line 90
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 91
    .line 92
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
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
