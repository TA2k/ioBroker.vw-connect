.class public final Lgb0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lif0/f0;

.field public final b:Len0/s;

.field public final c:Lez0/c;


# direct methods
.method public constructor <init>(Lif0/f0;Len0/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/p;->a:Lif0/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/p;->b:Len0/s;

    .line 7
    .line 8
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lgb0/p;->c:Lez0/c;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lgb0/p;->a:Lif0/f0;

    .line 2
    .line 3
    iget-object v0, v0, Lif0/f0;->g:Lwe0/a;

    .line 4
    .line 5
    check-cast v0, Lwe0/c;

    .line 6
    .line 7
    invoke-virtual {v0}, Lwe0/c;->b()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lgb0/p;->b:Len0/s;

    .line 14
    .line 15
    iget-object p0, p0, Len0/s;->e:Lwe0/a;

    .line 16
    .line 17
    check-cast p0, Lwe0/c;

    .line 18
    .line 19
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
