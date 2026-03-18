.class public final synthetic Lgg/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzi/a;

.field public final synthetic f:Lz9/y;


# direct methods
.method public synthetic constructor <init>(Lzi/a;Lz9/y;I)V
    .locals 0

    .line 1
    iput p3, p0, Lgg/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lgg/a;->e:Lzi/a;

    .line 4
    .line 5
    iput-object p2, p0, Lgg/a;->f:Lz9/y;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lgg/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    check-cast p3, Ll2/o;

    .line 8
    .line 9
    check-cast p4, Ljava/lang/Integer;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    const-string v0, "$this$composable"

    .line 15
    .line 16
    const-string v1, "it"

    .line 17
    .line 18
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lgg/a;->e:Lzi/a;

    .line 22
    .line 23
    iget-object p1, p1, Lzi/a;->d:Ljava/lang/String;

    .line 24
    .line 25
    check-cast p3, Ll2/t;

    .line 26
    .line 27
    iget-object v2, p0, Lgg/a;->f:Lz9/y;

    .line 28
    .line 29
    invoke-virtual {p3, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    if-nez p0, :cond_0

    .line 38
    .line 39
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 40
    .line 41
    if-ne p2, p0, :cond_1

    .line 42
    .line 43
    :cond_0
    new-instance v0, Lf20/h;

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    const/16 v7, 0x16

    .line 47
    .line 48
    const/4 v1, 0x0

    .line 49
    const-class v3, Lgg/b;

    .line 50
    .line 51
    const-string v4, "navigateToRemoteStart"

    .line 52
    .line 53
    const-string v5, "navigateToRemoteStart(Landroidx/navigation/NavHostController;)V"

    .line 54
    .line 55
    invoke-direct/range {v0 .. v7}, Lf20/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    move-object p2, v0

    .line 62
    :cond_1
    check-cast p2, Lhy0/g;

    .line 63
    .line 64
    check-cast p2, Lay0/a;

    .line 65
    .line 66
    const/4 p0, 0x0

    .line 67
    invoke-static {p1, p2, p3, p0}, Llp/ia;->d(Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 68
    .line 69
    .line 70
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object p0

    .line 73
    :pswitch_0
    const-string v0, "$this$composable"

    .line 74
    .line 75
    const-string v1, "it"

    .line 76
    .line 77
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    check-cast p3, Ll2/t;

    .line 81
    .line 82
    iget-object v2, p0, Lgg/a;->f:Lz9/y;

    .line 83
    .line 84
    invoke-virtual {p3, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    if-nez p1, :cond_2

    .line 93
    .line 94
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-ne p2, p1, :cond_3

    .line 97
    .line 98
    :cond_2
    new-instance v0, Lf20/h;

    .line 99
    .line 100
    const/4 v6, 0x1

    .line 101
    const/16 v7, 0x15

    .line 102
    .line 103
    const/4 v1, 0x0

    .line 104
    const-class v3, Lgg/b;

    .line 105
    .line 106
    const-string v4, "navigateToRemoteStop"

    .line 107
    .line 108
    const-string v5, "navigateToRemoteStop(Landroidx/navigation/NavHostController;)V"

    .line 109
    .line 110
    invoke-direct/range {v0 .. v7}, Lf20/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    move-object p2, v0

    .line 117
    :cond_3
    check-cast p2, Lhy0/g;

    .line 118
    .line 119
    check-cast p2, Lay0/a;

    .line 120
    .line 121
    const/4 p1, 0x0

    .line 122
    iget-object p0, p0, Lgg/a;->e:Lzi/a;

    .line 123
    .line 124
    invoke-static {p0, p2, p3, p1}, Llp/v0;->F(Lzi/a;Lay0/a;Ll2/o;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
