.class public final Lio/ktor/utils/io/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/ktor/utils/io/e;


# instance fields
.field public final b:Lvy0/l;

.field public final c:Ljava/lang/Throwable;


# direct methods
.method public constructor <init>(Lvy0/l;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/ktor/utils/io/f;->b:Lvy0/l;

    .line 5
    .line 6
    const-string v0, "io.ktor.development"

    .line 7
    .line 8
    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-static {v0}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v1, 0x1

    .line 19
    if-ne v0, v1, :cond_0

    .line 20
    .line 21
    new-instance v0, Ljava/lang/Throwable;

    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    const/16 v1, 0x10

    .line 28
    .line 29
    invoke-static {v1}, Lry/a;->a(I)V

    .line 30
    .line 31
    .line 32
    invoke-static {p1, v1}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    const-string v1, "toString(...)"

    .line 37
    .line 38
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v1, "WriteTask 0x"

    .line 42
    .line 43
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-direct {v0, p1}, Ljava/lang/Throwable;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0}, Loa0/b;->b(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    iput-object v0, p0, Lio/ktor/utils/io/f;->c:Ljava/lang/Throwable;

    .line 54
    .line 55
    :cond_0
    return-void
.end method


# virtual methods
.method public final c()Ljava/lang/Throwable;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/f;->c:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()Lkotlin/coroutines/Continuation;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/f;->b:Lvy0/l;

    .line 2
    .line 3
    return-object p0
.end method
