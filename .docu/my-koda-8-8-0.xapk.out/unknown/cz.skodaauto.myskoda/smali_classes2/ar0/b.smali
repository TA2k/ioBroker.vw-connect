.class public final Lar0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcr0/h;
.implements Lme0/a;
.implements Lme0/b;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lez0/c;

.field public final c:Lyy0/c2;

.field public final d:Lrz/k;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lar0/b;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lar0/b;->b:Lez0/c;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lar0/b;->c:Lyy0/c2;

    .line 18
    .line 19
    new-instance v0, Lrz/k;

    .line 20
    .line 21
    const/16 v1, 0x15

    .line 22
    .line 23
    invoke-direct {v0, p1, v1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lar0/b;->d:Lrz/k;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p1, p0, Lar0/b;->c:Lyy0/c2;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lar0/b;->a:Lwe0/a;

    .line 8
    .line 9
    check-cast p0, Lwe0/c;

    .line 10
    .line 11
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 12
    .line 13
    .line 14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0
.end method
