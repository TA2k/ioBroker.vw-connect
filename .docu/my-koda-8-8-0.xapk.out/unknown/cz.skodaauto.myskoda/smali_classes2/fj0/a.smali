.class public final Lfj0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfj0/e;


# direct methods
.method public constructor <init>(Lfj0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfj0/a;->a:Lfj0/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Locale;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lfj0/a;->b(Ljava/util/Locale;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method public final b(Ljava/util/Locale;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lfj0/a;->a:Lfj0/e;

    .line 2
    .line 3
    check-cast p0, Ldj0/b;

    .line 4
    .line 5
    const-string v0, "locale"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Ldj0/b;->e:Lyy0/q1;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method
