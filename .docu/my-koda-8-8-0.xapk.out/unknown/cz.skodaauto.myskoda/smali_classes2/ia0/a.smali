.class public final Lia0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lka0/b;
.implements Lme0/b;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lez0/c;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/c2;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lia0/a;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lia0/a;->b:Lez0/c;

    .line 11
    .line 12
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 13
    .line 14
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lia0/a;->c:Lyy0/c2;

    .line 19
    .line 20
    iput-object p1, p0, Lia0/a;->d:Lyy0/c2;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    :cond_0
    iget-object p1, p0, Lia0/a;->c:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lne0/s;

    .line 9
    .line 10
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lia0/a;->a:Lwe0/a;

    .line 19
    .line 20
    check-cast p0, Lwe0/c;

    .line 21
    .line 22
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
