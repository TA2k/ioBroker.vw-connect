.class public final Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0006\u0008\u0001\u0018\u0000 \n2\u00020\u0001:\u0001\u000bB\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J=\u0010\u0008\u001a0\u0012,\u0012*\u0012\u000e\u0008\u0001\u0012\n \u0007*\u0004\u0018\u00010\u00060\u0006 \u0007*\u0014\u0012\u000e\u0008\u0001\u0012\n \u0007*\u0004\u0018\u00010\u00060\u0006\u0018\u00010\u00050\u00050\u0004H\u0016\u00a2\u0006\u0004\u0008\u0008\u0010\t\u00a8\u0006\u000c"
    }
    d2 = {
        "Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;",
        "Lcom/google/firebase/components/ComponentRegistrar;",
        "<init>",
        "()V",
        "",
        "Lgs/b;",
        "",
        "kotlin.jvm.PlatformType",
        "getComponents",
        "()Ljava/util/List;",
        "Companion",
        "hu/s",
        "com.google.firebase-firebase-sessions"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final Companion:Lhu/s;

.field public static final LIBRARY_NAME:Ljava/lang/String; = "fire-sessions"
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end field

.field private static final appContext:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field

.field private static final backgroundDispatcher:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field

.field private static final blockingDispatcher:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field

.field private static final firebaseApp:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field

.field private static final firebaseInstallationsApi:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field

.field private static final firebaseSessionsComponent:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field

.field private static final transportFactory:Lgs/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lgs/s;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lhu/s;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->Companion:Lhu/s;

    .line 7
    .line 8
    const-class v0, Landroid/content/Context;

    .line 9
    .line 10
    invoke-static {v0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->appContext:Lgs/s;

    .line 15
    .line 16
    const-class v0, Lsr/f;

    .line 17
    .line 18
    invoke-static {v0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseApp:Lgs/s;

    .line 23
    .line 24
    const-class v0, Lht/d;

    .line 25
    .line 26
    invoke-static {v0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseInstallationsApi:Lgs/s;

    .line 31
    .line 32
    new-instance v0, Lgs/s;

    .line 33
    .line 34
    const-class v1, Lyr/a;

    .line 35
    .line 36
    const-class v2, Lvy0/x;

    .line 37
    .line 38
    invoke-direct {v0, v1, v2}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->backgroundDispatcher:Lgs/s;

    .line 42
    .line 43
    new-instance v0, Lgs/s;

    .line 44
    .line 45
    const-class v1, Lyr/b;

    .line 46
    .line 47
    invoke-direct {v0, v1, v2}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 48
    .line 49
    .line 50
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->blockingDispatcher:Lgs/s;

    .line 51
    .line 52
    const-class v0, Lon/f;

    .line 53
    .line 54
    invoke-static {v0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->transportFactory:Lgs/s;

    .line 59
    .line 60
    const-class v0, Lhu/p;

    .line 61
    .line 62
    invoke-static {v0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseSessionsComponent:Lgs/s;

    .line 67
    .line 68
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lin/z1;)Lhu/p;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->getComponents$lambda$1(Lgs/c;)Lhu/p;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getAppContext$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->appContext:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBackgroundDispatcher$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->backgroundDispatcher:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBlockingDispatcher$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->blockingDispatcher:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getFirebaseApp$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseApp:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getFirebaseInstallationsApi$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseInstallationsApi:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getFirebaseSessionsComponent$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseSessionsComponent:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getTransportFactory$cp()Lgs/s;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->transportFactory:Lgs/s;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic b(Lin/z1;)Lhu/n;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->getComponents$lambda$0(Lgs/c;)Lhu/n;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final getComponents$lambda$0(Lgs/c;)Lhu/n;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseSessionsComponent:Lgs/s;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lhu/p;

    .line 8
    .line 9
    check-cast p0, Lhu/i;

    .line 10
    .line 11
    iget-object p0, p0, Lhu/i;->p:Lju/c;

    .line 12
    .line 13
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lhu/n;

    .line 18
    .line 19
    return-object p0
.end method

.method private static final getComponents$lambda$1(Lgs/c;)Lhu/p;
    .locals 13

    .line 1
    sget-object v0, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->appContext:Lgs/s;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "get(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast v0, Landroid/content/Context;

    .line 13
    .line 14
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->backgroundDispatcher:Lgs/s;

    .line 15
    .line 16
    invoke-interface {p0, v2}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    check-cast v2, Lpx0/g;

    .line 24
    .line 25
    sget-object v3, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->blockingDispatcher:Lgs/s;

    .line 26
    .line 27
    invoke-interface {p0, v3}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    check-cast v3, Lpx0/g;

    .line 35
    .line 36
    sget-object v4, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseApp:Lgs/s;

    .line 37
    .line 38
    invoke-interface {p0, v4}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    check-cast v4, Lsr/f;

    .line 46
    .line 47
    sget-object v5, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseInstallationsApi:Lgs/s;

    .line 48
    .line 49
    invoke-interface {p0, v5}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    check-cast v5, Lht/d;

    .line 57
    .line 58
    sget-object v1, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->transportFactory:Lgs/s;

    .line 59
    .line 60
    invoke-interface {p0, v1}, Lgs/c;->e(Lgs/s;)Lgt/b;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const-string v1, "getProvider(...)"

    .line 65
    .line 66
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    new-instance v1, Lhu/i;

    .line 70
    .line 71
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 72
    .line 73
    .line 74
    invoke-static {v4}, Lj1/a;->c(Ljava/lang/Object;)Lj1/a;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    iput-object v4, v1, Lhu/i;->a:Lj1/a;

    .line 79
    .line 80
    invoke-static {v0}, Lj1/a;->c(Ljava/lang/Object;)Lj1/a;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    iput-object v0, v1, Lhu/i;->b:Lj1/a;

    .line 85
    .line 86
    new-instance v4, Lj1/a;

    .line 87
    .line 88
    const/16 v6, 0x8

    .line 89
    .line 90
    invoke-direct {v4, v0, v6}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    invoke-static {v4}, Lju/a;->a(Lju/b;)Lju/c;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iput-object v0, v1, Lhu/i;->c:Lju/c;

    .line 98
    .line 99
    sget-object v0, Lhu/r;->a:Lhu/o;

    .line 100
    .line 101
    invoke-static {v0}, Lju/a;->a(Lju/b;)Lju/c;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    iput-object v0, v1, Lhu/i;->d:Lju/c;

    .line 106
    .line 107
    invoke-static {v5}, Lj1/a;->c(Ljava/lang/Object;)Lj1/a;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    iput-object v0, v1, Lhu/i;->e:Lj1/a;

    .line 112
    .line 113
    iget-object v0, v1, Lhu/i;->a:Lj1/a;

    .line 114
    .line 115
    new-instance v4, Lhu/q;

    .line 116
    .line 117
    const/4 v5, 0x0

    .line 118
    invoke-direct {v4, v0, v5}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 119
    .line 120
    .line 121
    invoke-static {v4}, Lju/a;->a(Lju/b;)Lju/c;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    iput-object v0, v1, Lhu/i;->f:Lju/c;

    .line 126
    .line 127
    invoke-static {v3}, Lj1/a;->c(Ljava/lang/Object;)Lj1/a;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    iput-object v0, v1, Lhu/i;->g:Lj1/a;

    .line 132
    .line 133
    iget-object v3, v1, Lhu/i;->f:Lju/c;

    .line 134
    .line 135
    new-instance v4, Lb81/a;

    .line 136
    .line 137
    const/16 v5, 0xe

    .line 138
    .line 139
    invoke-direct {v4, v5, v3, v0}, Lb81/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    invoke-static {v4}, Lju/a;->a(Lju/b;)Lju/c;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    iput-object v0, v1, Lhu/i;->h:Lju/c;

    .line 147
    .line 148
    invoke-static {v2}, Lj1/a;->c(Ljava/lang/Object;)Lj1/a;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    iput-object v0, v1, Lhu/i;->i:Lj1/a;

    .line 153
    .line 154
    iget-object v0, v1, Lhu/i;->b:Lj1/a;

    .line 155
    .line 156
    iget-object v2, v1, Lhu/i;->g:Lj1/a;

    .line 157
    .line 158
    new-instance v3, Lb81/c;

    .line 159
    .line 160
    const/16 v4, 0x9

    .line 161
    .line 162
    invoke-direct {v3, v4, v0, v2}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    invoke-static {v3}, Lju/a;->a(Lju/b;)Lju/c;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    iget-object v2, v1, Lhu/i;->i:Lj1/a;

    .line 170
    .line 171
    iget-object v3, v1, Lhu/i;->d:Lju/c;

    .line 172
    .line 173
    new-instance v4, Lil/g;

    .line 174
    .line 175
    const/16 v5, 0x9

    .line 176
    .line 177
    invoke-direct {v4, v2, v3, v0, v5}, Lil/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 178
    .line 179
    .line 180
    invoke-static {v4}, Lju/a;->a(Lju/b;)Lju/c;

    .line 181
    .line 182
    .line 183
    move-result-object v11

    .line 184
    iget-object v7, v1, Lhu/i;->d:Lju/c;

    .line 185
    .line 186
    iget-object v8, v1, Lhu/i;->e:Lj1/a;

    .line 187
    .line 188
    iget-object v9, v1, Lhu/i;->f:Lju/c;

    .line 189
    .line 190
    iget-object v10, v1, Lhu/i;->h:Lju/c;

    .line 191
    .line 192
    new-instance v6, Landroidx/lifecycle/c1;

    .line 193
    .line 194
    const/16 v12, 0xf

    .line 195
    .line 196
    invoke-direct/range {v6 .. v12}, Landroidx/lifecycle/c1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 197
    .line 198
    .line 199
    invoke-static {v6}, Lju/a;->a(Lju/b;)Lju/c;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    iget-object v2, v1, Lhu/i;->c:Lju/c;

    .line 204
    .line 205
    new-instance v3, Lb81/b;

    .line 206
    .line 207
    const/16 v4, 0xe

    .line 208
    .line 209
    invoke-direct {v3, v4, v2, v0}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    invoke-static {v3}, Lju/a;->a(Lju/b;)Lju/c;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    iput-object v0, v1, Lhu/i;->j:Lju/c;

    .line 217
    .line 218
    sget-object v0, Lhu/r;->b:Lhu/o;

    .line 219
    .line 220
    invoke-static {v0}, Lju/a;->a(Lju/b;)Lju/c;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    iput-object v0, v1, Lhu/i;->k:Lju/c;

    .line 225
    .line 226
    iget-object v2, v1, Lhu/i;->d:Lju/c;

    .line 227
    .line 228
    new-instance v3, Lc2/k;

    .line 229
    .line 230
    const/16 v4, 0x9

    .line 231
    .line 232
    invoke-direct {v3, v4, v2, v0}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    invoke-static {v3}, Lju/a;->a(Lju/b;)Lju/c;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    iput-object v0, v1, Lhu/i;->l:Lju/c;

    .line 240
    .line 241
    invoke-static {p0}, Lj1/a;->c(Ljava/lang/Object;)Lj1/a;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    new-instance v0, Lh6/e;

    .line 246
    .line 247
    const/4 v2, 0x1

    .line 248
    invoke-direct {v0, p0, v2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 249
    .line 250
    .line 251
    invoke-static {v0}, Lju/a;->a(Lju/b;)Lju/c;

    .line 252
    .line 253
    .line 254
    move-result-object v7

    .line 255
    iget-object v4, v1, Lhu/i;->a:Lj1/a;

    .line 256
    .line 257
    iget-object v5, v1, Lhu/i;->e:Lj1/a;

    .line 258
    .line 259
    iget-object v6, v1, Lhu/i;->j:Lju/c;

    .line 260
    .line 261
    iget-object v8, v1, Lhu/i;->i:Lj1/a;

    .line 262
    .line 263
    new-instance v3, Landroidx/lifecycle/c1;

    .line 264
    .line 265
    const/16 v9, 0x9

    .line 266
    .line 267
    invoke-direct/range {v3 .. v9}, Landroidx/lifecycle/c1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 268
    .line 269
    .line 270
    invoke-static {v3}, Lju/a;->a(Lju/b;)Lju/c;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    iput-object p0, v1, Lhu/i;->m:Lju/c;

    .line 275
    .line 276
    iget-object p0, v1, Lhu/i;->l:Lju/c;

    .line 277
    .line 278
    new-instance v0, Lhu/g0;

    .line 279
    .line 280
    const/4 v2, 0x0

    .line 281
    invoke-direct {v0, p0, v2}, Lhu/g0;-><init>(Lkx0/a;I)V

    .line 282
    .line 283
    .line 284
    invoke-static {v0}, Lju/a;->a(Lju/b;)Lju/c;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    iget-object v0, v1, Lhu/i;->b:Lj1/a;

    .line 289
    .line 290
    iget-object v2, v1, Lhu/i;->g:Lj1/a;

    .line 291
    .line 292
    new-instance v3, Lgw0/c;

    .line 293
    .line 294
    const/16 v4, 0x1b

    .line 295
    .line 296
    invoke-direct {v3, v0, v2, p0, v4}, Lgw0/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 297
    .line 298
    .line 299
    invoke-static {v3}, Lju/a;->a(Lju/b;)Lju/c;

    .line 300
    .line 301
    .line 302
    move-result-object p0

    .line 303
    iput-object p0, v1, Lhu/i;->n:Lju/c;

    .line 304
    .line 305
    iget-object p0, v1, Lhu/i;->b:Lj1/a;

    .line 306
    .line 307
    iget-object v0, v1, Lhu/i;->k:Lju/c;

    .line 308
    .line 309
    new-instance v2, Lb81/d;

    .line 310
    .line 311
    const/4 v3, 0x7

    .line 312
    invoke-direct {v2, v3, p0, v0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    invoke-static {v2}, Lju/a;->a(Lju/b;)Lju/c;

    .line 316
    .line 317
    .line 318
    move-result-object v10

    .line 319
    iget-object v5, v1, Lhu/i;->j:Lju/c;

    .line 320
    .line 321
    iget-object v6, v1, Lhu/i;->l:Lju/c;

    .line 322
    .line 323
    iget-object v7, v1, Lhu/i;->m:Lju/c;

    .line 324
    .line 325
    iget-object v8, v1, Lhu/i;->d:Lju/c;

    .line 326
    .line 327
    iget-object v9, v1, Lhu/i;->n:Lju/c;

    .line 328
    .line 329
    iget-object v11, v1, Lhu/i;->i:Lj1/a;

    .line 330
    .line 331
    new-instance v4, Lss/b;

    .line 332
    .line 333
    const/4 v12, 0x5

    .line 334
    invoke-direct/range {v4 .. v12}, Lss/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 335
    .line 336
    .line 337
    invoke-static {v4}, Lju/a;->a(Lju/b;)Lju/c;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    iput-object p0, v1, Lhu/i;->o:Lju/c;

    .line 342
    .line 343
    new-instance v0, Lh6/e;

    .line 344
    .line 345
    const/4 v2, 0x2

    .line 346
    invoke-direct {v0, p0, v2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 347
    .line 348
    .line 349
    invoke-static {v0}, Lju/a;->a(Lju/b;)Lju/c;

    .line 350
    .line 351
    .line 352
    move-result-object v7

    .line 353
    iget-object v4, v1, Lhu/i;->a:Lj1/a;

    .line 354
    .line 355
    iget-object v5, v1, Lhu/i;->j:Lju/c;

    .line 356
    .line 357
    iget-object v6, v1, Lhu/i;->i:Lj1/a;

    .line 358
    .line 359
    new-instance v3, Lcom/google/firebase/messaging/w;

    .line 360
    .line 361
    const/16 v8, 0xe

    .line 362
    .line 363
    invoke-direct/range {v3 .. v8}, Lcom/google/firebase/messaging/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 364
    .line 365
    .line 366
    invoke-static {v3}, Lju/a;->a(Lju/b;)Lju/c;

    .line 367
    .line 368
    .line 369
    move-result-object p0

    .line 370
    iput-object p0, v1, Lhu/i;->p:Lju/c;

    .line 371
    .line 372
    return-object v1
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lgs/b;",
            ">;"
        }
    .end annotation

    .line 1
    const-class p0, Lhu/n;

    .line 2
    .line 3
    invoke-static {p0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "fire-sessions"

    .line 8
    .line 9
    iput-object v0, p0, Lgs/a;->a:Ljava/lang/String;

    .line 10
    .line 11
    sget-object v1, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseSessionsComponent:Lgs/s;

    .line 12
    .line 13
    invoke-static {v1}, Lgs/k;->b(Lgs/s;)Lgs/k;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {p0, v1}, Lgs/a;->a(Lgs/k;)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lf3/d;

    .line 21
    .line 22
    const/16 v2, 0x15

    .line 23
    .line 24
    invoke-direct {v1, v2}, Lf3/d;-><init>(I)V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Lgs/a;->f:Lgs/e;

    .line 28
    .line 29
    const/4 v1, 0x2

    .line 30
    invoke-virtual {p0, v1}, Lgs/a;->c(I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lgs/a;->b()Lgs/b;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-class v1, Lhu/p;

    .line 38
    .line 39
    invoke-static {v1}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    const-string v2, "fire-sessions-component"

    .line 44
    .line 45
    iput-object v2, v1, Lgs/a;->a:Ljava/lang/String;

    .line 46
    .line 47
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->appContext:Lgs/s;

    .line 48
    .line 49
    invoke-static {v2}, Lgs/k;->b(Lgs/s;)Lgs/k;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 54
    .line 55
    .line 56
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->backgroundDispatcher:Lgs/s;

    .line 57
    .line 58
    invoke-static {v2}, Lgs/k;->b(Lgs/s;)Lgs/k;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 63
    .line 64
    .line 65
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->blockingDispatcher:Lgs/s;

    .line 66
    .line 67
    invoke-static {v2}, Lgs/k;->b(Lgs/s;)Lgs/k;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 72
    .line 73
    .line 74
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseApp:Lgs/s;

    .line 75
    .line 76
    invoke-static {v2}, Lgs/k;->b(Lgs/s;)Lgs/k;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 81
    .line 82
    .line 83
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->firebaseInstallationsApi:Lgs/s;

    .line 84
    .line 85
    invoke-static {v2}, Lgs/k;->b(Lgs/s;)Lgs/k;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 90
    .line 91
    .line 92
    sget-object v2, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->transportFactory:Lgs/s;

    .line 93
    .line 94
    new-instance v3, Lgs/k;

    .line 95
    .line 96
    const/4 v4, 0x1

    .line 97
    invoke-direct {v3, v2, v4, v4}, Lgs/k;-><init>(Lgs/s;II)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v1, v3}, Lgs/a;->a(Lgs/k;)V

    .line 101
    .line 102
    .line 103
    new-instance v2, Lf3/d;

    .line 104
    .line 105
    const/16 v3, 0x16

    .line 106
    .line 107
    invoke-direct {v2, v3}, Lf3/d;-><init>(I)V

    .line 108
    .line 109
    .line 110
    iput-object v2, v1, Lgs/a;->f:Lgs/e;

    .line 111
    .line 112
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    const-string v2, "3.0.3"

    .line 117
    .line 118
    invoke-static {v0, v2}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    filled-new-array {p0, v1, v0}, [Lgs/b;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0
.end method
