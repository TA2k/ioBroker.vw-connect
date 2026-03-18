.class public final Lfo0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ldo0/a;


# direct methods
.method public constructor <init>(Ldo0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfo0/c;->a:Ldo0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgo0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lfo0/c;->b(Lgo0/a;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lgo0/a;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object p0, p0, Lfo0/c;->a:Ldo0/a;

    .line 2
    .line 3
    iget-object v0, p0, Ldo0/a;->b:Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lgo0/c;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    if-ne v0, p0, :cond_0

    .line 19
    .line 20
    new-instance v1, Lne0/c;

    .line 21
    .line 22
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p0, "Player is not initialized."

    .line 25
    .line 26
    invoke-direct {v2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    const/16 v6, 0x1e

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    const/4 v4, 0x0

    .line 34
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    :cond_0
    new-instance p0, La8/r0;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    const-string v0, "mediaSource"

    .line 45
    .line 46
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Ldo0/a;->a:Lyy0/q1;

    .line 50
    .line 51
    new-instance v0, Lgo0/b;

    .line 52
    .line 53
    invoke-direct {v0, p1}, Lgo0/b;-><init>(Lgo0/a;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    new-instance p0, Lne0/e;

    .line 60
    .line 61
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    return-object p0
.end method
