.class public final Lg30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li30/d;
.implements Lme0/a;
.implements Lme0/b;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lez0/c;

.field public c:Z

.field public final d:Lyy0/c2;

.field public final e:Lyy0/c2;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg30/a;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lg30/a;->b:Lez0/c;

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    iput-boolean p1, p0, Lg30/a;->c:Z

    .line 14
    .line 15
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 16
    .line 17
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lg30/a;->d:Lyy0/c2;

    .line 22
    .line 23
    iput-object p1, p0, Lg30/a;->e:Lyy0/c2;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    const/4 p1, 0x1

    .line 2
    iput-boolean p1, p0, Lg30/a;->c:Z

    .line 3
    .line 4
    iget-object p0, p0, Lg30/a;->a:Lwe0/a;

    .line 5
    .line 6
    check-cast p0, Lwe0/c;

    .line 7
    .line 8
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method
