.class public final Ljk0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llk0/h;
.implements Lme0/a;
.implements Lme0/b;


# static fields
.field public static final e:Lne0/c;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lez0/c;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lne0/c;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/Exception;

    .line 4
    .line 5
    const-string v2, "No data"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    const/16 v5, 0x1e

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Ljk0/a;->e:Lne0/c;

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(Lwe0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljk0/a;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Ljk0/a;->b:Lez0/c;

    .line 11
    .line 12
    sget-object p1, Ljk0/a;->e:Lne0/c;

    .line 13
    .line 14
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Ljk0/a;->c:Lyy0/c2;

    .line 19
    .line 20
    new-instance v0, Lyy0/l1;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Ljk0/a;->d:Lyy0/l1;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p1, p0, Ljk0/a;->c:Lyy0/c2;

    .line 2
    .line 3
    sget-object v0, Ljk0/a;->e:Lne0/c;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Ljk0/a;->a:Lwe0/a;

    .line 9
    .line 10
    check-cast p0, Lwe0/c;

    .line 11
    .line 12
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0
.end method
