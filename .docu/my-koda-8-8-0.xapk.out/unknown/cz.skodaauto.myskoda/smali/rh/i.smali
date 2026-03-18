.class public final synthetic Lrh/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lrh/u;


# direct methods
.method public synthetic constructor <init>(Lrh/u;I)V
    .locals 0

    .line 1
    iput p2, p0, Lrh/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrh/i;->e:Lrh/u;

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
    .locals 10

    .line 1
    iget v0, p0, Lrh/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v3, p0, Lrh/i;->e:Lrh/u;

    .line 7
    .line 8
    iget-object v0, v3, Lrh/u;->h:Lyy0/c2;

    .line 9
    .line 10
    new-instance v1, Lo90/f;

    .line 11
    .line 12
    const/4 v7, 0x0

    .line 13
    const/16 v8, 0x18

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-class v4, Lrh/u;

    .line 17
    .line 18
    const-string v5, "checkPairingCodeIsValid"

    .line 19
    .line 20
    const-string v6, "checkPairingCodeIsValid(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/pairing/ConfigFieldPresentation;)Z"

    .line 21
    .line 22
    invoke-direct/range {v1 .. v8}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 23
    .line 24
    .line 25
    const-string p0, "<this>"

    .line 26
    .line 27
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    move-object v2, p0

    .line 35
    check-cast v2, Lrh/v;

    .line 36
    .line 37
    iget-object v3, v2, Lrh/v;->b:Ljava/util/List;

    .line 38
    .line 39
    check-cast v3, Ljava/lang/Iterable;

    .line 40
    .line 41
    new-instance v4, Ljava/util/ArrayList;

    .line 42
    .line 43
    const/16 v5, 0xa

    .line 44
    .line 45
    invoke-static {v3, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_2

    .line 61
    .line 62
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Lrh/d;

    .line 67
    .line 68
    invoke-virtual {v1, v5}, Lo90/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    check-cast v6, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    if-eqz v6, :cond_1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    const/4 v6, 0x1

    .line 82
    const/16 v7, 0xf7

    .line 83
    .line 84
    const/4 v8, 0x0

    .line 85
    invoke-static {v5, v8, v6, v7}, Lrh/d;->a(Lrh/d;Ljava/lang/String;ZI)Lrh/d;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    :goto_1
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_2
    const/4 v8, 0x0

    .line 94
    const/16 v9, 0x7d

    .line 95
    .line 96
    const/4 v3, 0x0

    .line 97
    const/4 v5, 0x0

    .line 98
    const/4 v6, 0x0

    .line 99
    const/4 v7, 0x0

    .line 100
    invoke-static/range {v2 .. v9}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    invoke-virtual {v0, p0, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    if-eqz p0, :cond_0

    .line 109
    .line 110
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_0
    iget-object p0, p0, Lrh/i;->e:Lrh/u;

    .line 114
    .line 115
    sget-object v0, Lrh/j;->a:Lrh/j;

    .line 116
    .line 117
    invoke-virtual {p0, v0}, Lrh/u;->d(Lrh/r;)V

    .line 118
    .line 119
    .line 120
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
