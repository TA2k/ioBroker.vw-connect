.class public final synthetic Lhs/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Runnable;

.field public final synthetic f:La0/j;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Runnable;La0/j;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhs/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhs/c;->e:Ljava/lang/Runnable;

    .line 4
    .line 5
    iput-object p2, p0, Lhs/c;->f:La0/j;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget v0, p0, Lhs/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhs/c;->e:Ljava/lang/Runnable;

    .line 7
    .line 8
    iget-object p0, p0, Lhs/c;->f:La0/j;

    .line 9
    .line 10
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lhs/h;

    .line 13
    .line 14
    :try_start_0
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-virtual {p0, v0}, Ly4/g;->j(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catch_0
    move-exception v0

    .line 23
    invoke-virtual {p0, v0}, Ly4/g;->k(Ljava/lang/Throwable;)Z

    .line 24
    .line 25
    .line 26
    :goto_0
    return-void

    .line 27
    :pswitch_0
    iget-object v0, p0, Lhs/c;->e:Ljava/lang/Runnable;

    .line 28
    .line 29
    :try_start_1
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 30
    .line 31
    .line 32
    goto :goto_1

    .line 33
    :catch_1
    move-exception v0

    .line 34
    iget-object p0, p0, Lhs/c;->f:La0/j;

    .line 35
    .line 36
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lhs/h;

    .line 39
    .line 40
    invoke-virtual {p0, v0}, Ly4/g;->k(Ljava/lang/Throwable;)Z

    .line 41
    .line 42
    .line 43
    :goto_1
    return-void

    .line 44
    :pswitch_1
    iget-object v0, p0, Lhs/c;->e:Ljava/lang/Runnable;

    .line 45
    .line 46
    :try_start_2
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :catch_2
    move-exception v0

    .line 51
    iget-object p0, p0, Lhs/c;->f:La0/j;

    .line 52
    .line 53
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lhs/h;

    .line 56
    .line 57
    invoke-virtual {p0, v0}, Ly4/g;->k(Ljava/lang/Throwable;)Z

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
