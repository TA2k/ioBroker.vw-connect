.class public final Ljj0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ldj0/b;

.field public final b:Lfj0/i;

.field public final c:Lhu/q;


# direct methods
.method public constructor <init>(Ldj0/b;Lfj0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljj0/e;->a:Ldj0/b;

    .line 5
    .line 6
    iput-object p2, p0, Ljj0/e;->b:Lfj0/i;

    .line 7
    .line 8
    new-instance p1, Lhu/q;

    .line 9
    .line 10
    const/4 p2, 0x7

    .line 11
    invoke-direct {p1, p0, p2}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Ljj0/e;->c:Lhu/q;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/Locale;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Luw/c;->a:Lcom/google/android/material/datepicker/d;

    .line 6
    .line 7
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v4, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v5, "Setting custom Locale Code: "

    .line 15
    .line 16
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-static {v4}, Let/d;->c(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v4, v1, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v4, Luw/b;

    .line 32
    .line 33
    const/4 v5, 0x7

    .line 34
    invoke-static {v4, v3, v0, v5}, Luw/b;->a(Luw/b;Ljava/util/Locale;Ljava/lang/String;I)Luw/b;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {v1, v0}, Lcom/google/android/material/datepicker/d;->a(Luw/b;)V

    .line 39
    .line 40
    .line 41
    move-object v0, v2

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    move-object v0, v3

    .line 44
    :goto_0
    const-string v1, "Phrase has not been initialized"

    .line 45
    .line 46
    if-nez v0, :cond_1

    .line 47
    .line 48
    invoke-static {v1}, Let/d;->d(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    sget-object v0, Luw/c;->a:Lcom/google/android/material/datepicker/d;

    .line 52
    .line 53
    if-eqz v0, :cond_2

    .line 54
    .line 55
    const/4 v4, 0x1

    .line 56
    invoke-static {v0, v3, v3, v4}, Lcom/google/android/material/datepicker/d;->i(Lcom/google/android/material/datepicker/d;Luw/b;Lhu/q;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    move-object v2, v3

    .line 61
    :goto_1
    if-nez v2, :cond_3

    .line 62
    .line 63
    invoke-static {v1}, Let/d;->d(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    :cond_3
    iget-object p0, p0, Ljj0/e;->a:Ldj0/b;

    .line 67
    .line 68
    iget-object p0, p0, Ldj0/b;->g:Lyy0/c2;

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    return-void
.end method
