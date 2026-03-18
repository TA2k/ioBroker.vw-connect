.class public final synthetic Lw7/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;


# instance fields
.field public final synthetic d:Le30/v;


# direct methods
.method public synthetic constructor <init>(Le30/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw7/i;->d:Le30/v;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Lw7/i;->d:Le30/v;

    .line 2
    .line 3
    iget-object p1, p0, Le30/v;->f:Ljava/io/Serializable;

    .line 4
    .line 5
    check-cast p1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x1

    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lw7/l;

    .line 23
    .line 24
    iget-object v2, p0, Le30/v;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v2, Lw7/k;

    .line 27
    .line 28
    iget-boolean v3, v0, Lw7/l;->d:Z

    .line 29
    .line 30
    if-nez v3, :cond_1

    .line 31
    .line 32
    iget-boolean v3, v0, Lw7/l;->c:Z

    .line 33
    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    iget-object v3, v0, Lw7/l;->b:Lb6/f;

    .line 37
    .line 38
    invoke-virtual {v3}, Lb6/f;->i()Lt7/m;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    new-instance v4, Lb6/f;

    .line 43
    .line 44
    invoke-direct {v4}, Lb6/f;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object v4, v0, Lw7/l;->b:Lb6/f;

    .line 48
    .line 49
    const/4 v4, 0x0

    .line 50
    iput-boolean v4, v0, Lw7/l;->c:Z

    .line 51
    .line 52
    iget-object v0, v0, Lw7/l;->a:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-interface {v2, v0, v3}, Lw7/k;->a(Ljava/lang/Object;Lt7/m;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    iget-object v0, p0, Le30/v;->d:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Lw7/t;

    .line 60
    .line 61
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Landroid/os/Handler;->hasMessages(I)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_0

    .line 68
    .line 69
    :cond_2
    return v1
.end method
