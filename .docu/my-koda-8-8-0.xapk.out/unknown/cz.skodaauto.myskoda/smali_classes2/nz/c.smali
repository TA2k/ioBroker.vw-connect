.class public final Lnz/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnz/j;


# direct methods
.method public synthetic constructor <init>(Lnz/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lnz/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnz/c;->e:Lnz/j;

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
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lnz/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ljava/lang/Boolean;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 13
    .line 14
    .line 15
    move-result v13

    .line 16
    iget-object v0, v0, Lnz/c;->e:Lnz/j;

    .line 17
    .line 18
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Lnz/e;

    .line 24
    .line 25
    const/4 v14, 0x0

    .line 26
    const/16 v15, 0x2fff

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v5, 0x0

    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v7, 0x0

    .line 33
    const/4 v8, 0x0

    .line 34
    const/4 v9, 0x0

    .line 35
    const/4 v10, 0x0

    .line 36
    const/4 v11, 0x0

    .line 37
    const/4 v12, 0x0

    .line 38
    invoke-static/range {v2 .. v15}, Lnz/e;->a(Lnz/e;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLnz/d;Llf0/i;ZZZI)Lnz/e;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 43
    .line 44
    .line 45
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object v0

    .line 48
    :pswitch_0
    move-object/from16 v1, p1

    .line 49
    .line 50
    check-cast v1, Lss0/j0;

    .line 51
    .line 52
    new-instance v1, Lnz/e;

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    const/16 v3, 0x3fff

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    invoke-direct {v1, v4, v3, v2, v2}, Lnz/e;-><init>(Ljava/lang/String;IZZ)V

    .line 59
    .line 60
    .line 61
    iget-object v0, v0, Lnz/c;->e:Lnz/j;

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 64
    .line 65
    .line 66
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object v0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
