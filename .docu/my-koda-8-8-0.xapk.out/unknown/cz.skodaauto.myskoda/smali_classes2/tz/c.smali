.class public final Ltz/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltz/s;


# direct methods
.method public synthetic constructor <init>(Ltz/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltz/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/c;->e:Ltz/s;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltz/c;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v0, v0, Ltz/c;->e:Ltz/s;

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lss0/j0;

    .line 15
    .line 16
    new-instance v3, Ltz/i;

    .line 17
    .line 18
    const/4 v7, 0x0

    .line 19
    const v8, 0xfffff

    .line 20
    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x0

    .line 25
    invoke-direct/range {v3 .. v8}, Ltz/i;-><init>(Ltz/g;Llf0/i;Ltz/h;ZI)V

    .line 26
    .line 27
    .line 28
    sget-object v1, Ltz/s;->z:Ljava/util/List;

    .line 29
    .line 30
    invoke-virtual {v0, v3}, Lql0/j;->g(Lql0/h;)V

    .line 31
    .line 32
    .line 33
    return-object v2

    .line 34
    :pswitch_0
    move-object/from16 v1, p1

    .line 35
    .line 36
    check-cast v1, Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 39
    .line 40
    .line 41
    move-result v11

    .line 42
    sget-object v1, Ltz/s;->z:Ljava/util/List;

    .line 43
    .line 44
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    move-object v3, v1

    .line 49
    check-cast v3, Ltz/i;

    .line 50
    .line 51
    const/16 v23, 0x0

    .line 52
    .line 53
    const v24, 0xfff7f

    .line 54
    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    const/4 v5, 0x0

    .line 58
    const/4 v6, 0x0

    .line 59
    const/4 v7, 0x0

    .line 60
    const/4 v8, 0x0

    .line 61
    const/4 v9, 0x0

    .line 62
    const/4 v10, 0x0

    .line 63
    const/4 v12, 0x0

    .line 64
    const/4 v13, 0x0

    .line 65
    const/4 v14, 0x0

    .line 66
    const/4 v15, 0x0

    .line 67
    const/16 v16, 0x0

    .line 68
    .line 69
    const/16 v17, 0x0

    .line 70
    .line 71
    const/16 v18, 0x0

    .line 72
    .line 73
    const/16 v19, 0x0

    .line 74
    .line 75
    const/16 v20, 0x0

    .line 76
    .line 77
    const/16 v21, 0x0

    .line 78
    .line 79
    const/16 v22, 0x0

    .line 80
    .line 81
    invoke-static/range {v3 .. v24}, Ltz/i;->a(Ltz/i;Ltz/g;Ljava/lang/String;ZZLlf0/i;Ltz/h;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/l;ZZZZZI)Ltz/i;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 86
    .line 87
    .line 88
    return-object v2

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
