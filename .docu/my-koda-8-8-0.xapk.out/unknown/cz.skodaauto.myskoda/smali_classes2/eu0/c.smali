.class public final Leu0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/l;


# direct methods
.method public synthetic constructor <init>(Lvy0/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Leu0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Leu0/c;->e:Lvy0/l;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onComplete(Laq/j;)V
    .locals 7

    .line 1
    iget v0, p0, Leu0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    move-object v0, p1

    .line 13
    check-cast v0, Laq/t;

    .line 14
    .line 15
    iget-boolean v0, v0, Laq/t;->d:Z

    .line 16
    .line 17
    iget-object p0, p0, Leu0/c;->e:Lvy0/l;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    invoke-virtual {p0, p1}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    iget-object p0, p0, Leu0/c;->e:Lvy0/l;

    .line 35
    .line 36
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    :goto_0
    return-void

    .line 44
    :pswitch_0
    iget-object p0, p0, Leu0/c;->e:Lvy0/l;

    .line 45
    .line 46
    const-string v0, "it"

    .line 47
    .line 48
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    new-instance p1, Lne0/e;

    .line 58
    .line 59
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    invoke-direct {p1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    new-instance v1, Lne0/c;

    .line 69
    .line 70
    new-instance v2, Ljava/lang/Exception;

    .line 71
    .line 72
    const-string p1, "Failed to update WearableData."

    .line 73
    .line 74
    invoke-direct {v2, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const/4 v5, 0x0

    .line 78
    const/16 v6, 0x1e

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    const/4 v4, 0x0

    .line 82
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p0, v1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :goto_1
    return-void

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
